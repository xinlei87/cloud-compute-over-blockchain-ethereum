// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/Nik-U/pbc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/ripemd160"
	//ABEO
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):  &ecrecover{},
	common.BytesToAddress([]byte{2}):  &sha256hash{},
	common.BytesToAddress([]byte{3}):  &ripemd160hash{},
	common.BytesToAddress([]byte{4}):  &dataCopy{},
	common.BytesToAddress([]byte{14}): &veriCipher{},
	common.BytesToAddress([]byte{15}): &veriTV{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):  &ecrecover{},
	common.BytesToAddress([]byte{2}):  &sha256hash{},
	common.BytesToAddress([]byte{3}):  &ripemd160hash{},
	common.BytesToAddress([]byte{4}):  &dataCopy{},
	common.BytesToAddress([]byte{5}):  &bigModExp{},
	common.BytesToAddress([]byte{6}):  &bn256Add{},
	common.BytesToAddress([]byte{7}):  &bn256ScalarMul{},
	common.BytesToAddress([]byte{8}):  &bn256Pairing{},
	common.BytesToAddress([]byte{14}): &veriCipher{},
	common.BytesToAddress([]byte{15}): &veriTV{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(input)
	if contract.UseGas(gas) {
		return p.Run(input)
	}
	return nil, ErrOutOfGas
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], append(input[64:128], v))
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
func (c *dataCopy) Run(in []byte) ([]byte, error) {
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct{}

var (
	big1      = big.NewInt(1)
	big4      = big.NewInt(4)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))

	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	switch {
	case gas.Cmp(big64) <= 0:
		gas.Mul(gas, gas)
	case gas.Cmp(big1024) <= 0:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, gas), big3072),
		)
	default:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, gas), big199680),
		)
	}
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, new(big.Int).SetUint64(params.ModExpQuadCoeffDiv))

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// bn256Add implements a native elliptic curve point addition.
type bn256Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256Add) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGas
}

func (c *bn256Add) Run(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256ScalarMul implements a native elliptic curve scalar multiplication.
type bn256ScalarMul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGas
}

func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// bn256Pairing implements a pairing pre-compile for the bn256 curve
type bn256Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256Pairing) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGas + uint64(len(input)/192)*params.Bn256PairingPerPointGas
}

func (c *bn256Pairing) Run(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

//ABOE

type veriCipher struct{}

func (c *veriCipher) RequiredGas(input []byte) uint64 {
	return params.VeriCipherGas
}
func (c *veriCipher) Run(input []byte) ([]byte, error) {
	//输入参数转化格式
	// fmt.Println("\n\n\nthis is veriTV\n\n\n")
	inputstrings := string(input)
	// fmt.Println(inputstrings)
	strarry := strings.Split(inputstrings, "#")
	CTstr := strarry[0]
	sigstr := strarry[1]
	wkeystr := strarry[2]

	// 验证数字签名
	x := "28126393105534499844491643222365191633009819397978928136324307863797025799826392896504160681368146936224101503199803"
	y := "27952977125817235228458522778224406172679477709881127170323567934678551503367564891609181639945741566596193739505449"
	xtemp, _ := new(big.Int).SetString(x, 10)
	ytemp, _ := new(big.Int).SetString(y, 10)
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     xtemp,
		Y:     ytemp,
	}
	var sigmap map[string]*big.Int
	sigstr = strings.Replace(sigstr, "'", "\"", -1)
	input = []byte(sigstr)
	json.Unmarshal(input, &sigmap)
	// 假设验证通过
	ecdsa.Verify(pub, []byte(CTstr), sigmap["r"], sigmap["s"])
	var CTmap map[string]string
	CTstr = strings.Replace(CTstr, "'", "\"", -1)
	CTstr = strings.Replace(CTstr, "[", "\"[", -1)
	CTstr = strings.Replace(CTstr, "]", "]\"", -1)
	input = []byte(CTstr)
	json.Unmarshal(input, &CTmap)
	// fmt.Println(CTmap)
	// fmt.Println(isok)
	ecstr := `type a
	q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
	h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
	r 730750818665451621361119245571504901405976559617
	exp2 159
	exp1 107
	sign1 1
	sign0 1
	`
	pairing, _ := pbc.NewPairingFromString(ecstr)
	cpr, _ := pairing.NewGT().SetString(CTmap["c0"], 10)
	yy, _ := pairing.NewZr().SetString(wkeystr, 10)
	cc := cpr.PowZn(cpr, yy).String()
	result := 0
	if cc == CTmap["c1"] {
		result = 1
	}

	bytes32Ans := make([]byte, 0, 32)

	for i := 0; i < 31; i++ {
		bytes32Ans = append(bytes32Ans, 0)
	}
	if result == 1 {
		bytes32Ans = append(bytes32Ans, 1) // verify successfully
	} else {
		bytes32Ans = append(bytes32Ans, 0) // verify unsuccessfully
	}

	return bytes32Ans, nil
}

type veriTV struct{}

func (c *veriTV) RequiredGas(input []byte) uint64 {
	return params.VeriTVGas
}

type tkdata struct {
	Tk1 string
	Tk2 string
	Tk3 map[string]string
	Tk4 map[string]string
}
type vkdata struct {
	Vk1 string
	Vk2 string
	Vk3 map[string]string
	Vk4 map[string]string
}
type rkyesdata struct {
	Attr map[string]*big.Int
	Rpr  *big.Int
	Ripr map[string]*big.Int
}

func (c *veriTV) Run(input []byte) ([]byte, error) {
	bytes32Ans := make([]byte, 0, 32)
	for i := 0; i < 31; i++ {
		bytes32Ans = append(bytes32Ans, 0)
	}
	//输入参数转化格式
	inputstrings := string(input)
	// fmt.Println("input is ", inputstrings)
	strarry := strings.Split(inputstrings, "#")
	// fmt.Println(tkvkstr)
	rkeysstr := strarry[0]
	pkstr := strarry[1]
	tkstr := strarry[2]
	vkstr := strarry[3]
	wkstr := strarry[4]
	keyshash := strarry[5]
	// -------------检测hash值-----------------
	hash := sha256.New()
	// fmt.Println(pkstr + tkstr + vkstr)
	hash.Write([]byte(pkstr + tkstr + vkstr))
	temphash := hex.EncodeToString(hash.Sum(nil))
	if temphash != keyshash {
		bytes32Ans = append(bytes32Ans, 0)
		return bytes32Ans, nil
	}
	// ------------转化数据格式------------
	//pk
	var pkstrmap map[string]string
	pkstr = strings.Replace(pkstr, "'", "\"", -1)
	pkstr = strings.Replace(pkstr, "[", "\"[", -1)
	pkstr = strings.Replace(pkstr, "]", "]\"", -1)
	input = []byte(pkstr)
	json.Unmarshal(input, &pkstrmap)
	//tk
	tkstr = strings.Replace(tkstr, "'", "\"", -1)
	tkstr = strings.Replace(tkstr, "[", "\"[", -1)
	tkstr = strings.Replace(tkstr, "]", "]\"", -1)
	tkstrmap := tkdata{}
	input = []byte(tkstr)
	json.Unmarshal(input, &tkstrmap)
	//vk
	vkstr = strings.Replace(vkstr, "'", "\"", -1)
	vkstr = strings.Replace(vkstr, "[", "\"[", -1)
	vkstr = strings.Replace(vkstr, "]", "]\"", -1)
	vkstrmap := vkdata{}
	input = []byte(vkstr)
	json.Unmarshal(input, &vkstrmap)

	//检测参数
	//rkey
	rkeysstr = strings.Replace(rkeysstr, "'", "\"", -1)
	rkeysintmap := rkyesdata{}
	input = []byte(rkeysstr)
	json.Unmarshal(input, &rkeysintmap)

	//椭圆曲线的计算
	str := `type a
	q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
	h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
	r 730750818665451621361119245571504901405976559617
	exp2 159
	exp1 107
	sign1 1
	sign0 1
	`

	pairing, _ := pbc.NewPairingFromString(str)
	// //格式转化，string转element类型
	g, _ := pairing.NewG1().SetString(pkstrmap["g"], 10)
	w, _ := pairing.NewG2().SetString(pkstrmap["w"], 10)
	h, _ := pairing.NewG2().SetString(pkstrmap["h"], 10)
	u, _ := pairing.NewG2().SetString(pkstrmap["u"], 10)
	v, _ := pairing.NewG2().SetString(pkstrmap["v"], 10)
	r := pairing.NewZr().SetBig(rkeysintmap.Rpr)
	t1, _ := pairing.NewZr().SetString(wkstr, 10)

	// //验证tk1，vk1
	tk1, _ := pairing.NewG2().SetString(tkstrmap.Tk1, 10)
	temp := pairing.NewG2()
	temp.PowZn(w, r)
	temp.Mul(tk1, temp)
	temp.PowZn(temp, t1)
	tempstr := temp.String()
	if tempstr != vkstrmap.Vk1 {
		bytes32Ans = append(bytes32Ans, 0) // verify unsuccessfully
		return bytes32Ans, nil
	}
	// //验证tk2，vk2
	tk2, _ := pairing.NewG1().SetString(tkstrmap.Tk2, 10)
	temp = pairing.NewG1()
	temp.PowZn(g, r)
	temp.Mul(tk2, temp)
	temp.PowZn(temp, t1)
	tempstr = temp.String()
	if tempstr != vkstrmap.Vk2 {
		bytes32Ans = append(bytes32Ans, 0) // verify unsuccessfully
		return bytes32Ans, nil
	}
	// //验证tki3,vki3
	temp = pairing.NewG1()
	for k, v := range rkeysintmap.Ripr {
		ri := pairing.NewZr().SetBig(v)
		temp.PowZn(g, ri)
		tki3, _ := pairing.NewG1().SetString(tkstrmap.Tk3[k], 10)
		temp.Mul(tki3, temp)
		temp.PowZn(temp, t1)
		tempstr = temp.String()
		if tempstr != vkstrmap.Vk3[k] {
			bytes32Ans = append(bytes32Ans, 0) // verify unsuccessfully
			return bytes32Ans, nil
		}
	}
	// //验证tki4,vki4
	temp = pairing.NewG2()
	for k, value := range rkeysintmap.Attr {
		ai := pairing.NewZr().SetBig(value)
		ri := pairing.NewZr().SetBig(rkeysintmap.Ripr[k])
		tki4, _ := pairing.NewG2().SetString(tkstrmap.Tk4[k], 10)
		temp.PowZn(u, ai)
		temp.Mul(temp, h)
		temp.PowZn(temp, ri)
		temp.Mul(tki4, temp)
		temp2 := pairing.NewG2()
		temp2.PowZn(v, r)
		temp.Div(temp, temp2)
		temp.PowZn(temp, t1)
		tempstr = temp.String()
		if tempstr != vkstrmap.Vk4[k] {
			bytes32Ans = append(bytes32Ans, 0) // verify unsuccessfully
			// fmt.Println("it is not ok")
			return bytes32Ans, nil
		}
	}
	bytes32Ans = append(bytes32Ans, 1) // verify successfully

	return bytes32Ans, nil
}
