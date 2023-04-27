/**
 * EVM From Scratch
 * Go template
 *
 * To work on EVM From Scratch in Go:
 *
 * - Install Golang: https://golang.org/doc/install
 * - Go to the `go` directory: `cd go`
 * - Edit `evm.go` (this file!), see TODO below
 * - Run `go run evm.go` to run the tests
 */

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"io/ioutil"
	"log"
	"math/big"
)

var (
	Big1       = uint256.NewInt(1)
	Big2       = uint256.NewInt(2)
	Big3       = uint256.NewInt(3)
	Big0       = uint256.NewInt(0)
	Big32      = uint256.NewInt(32)
	Big256     = uint256.NewInt(256)
	Big257     = uint256.NewInt(257)
	MaxUint256 = new(uint256.Int).Sub(new(uint256.Int).Lsh(Big1, 256), Big1)
)

type code struct {
	Bin string
	Asm string
}

type Transaction struct {
	From     string
	To       string
	Origin   string
	Gasprice string
	Value    string
	Data     string
}

type expect struct {
	Stack   []string
	Success bool
	Return  string
}

type TestCase struct {
	Name   string
	Block  Block
	Code   code
	Tx     Transaction
	State  map[common.Address]Storage `json:"state"`
	Expect expect
}

type Storage struct {
	Balance string `json:"balance"`
	Code    code   `json:"code"`
}

type Block struct {
	Coinbase   string `json:"coinbase"`
	Timestamp  string `json:"timestamp"`
	Number     string `json:"number"`
	Difficulty string `json:"difficulty"`
	GasLimit   string `json:"gaslimit"`
	ChainId    string `json:"chainid"`
}

type Memory struct {
	store []byte
}

type Contract struct {
	CallerAddress common.Address
	caller        common.Address
	self          common.Address

	Input []byte
	Gas   *big.Int
	value *big.Int
}

// Caller returns the caller of the contract.
//
// Caller will recursively call caller when the contract is a delegate
// call, including that of caller's caller.
func (c *Contract) Caller() common.Address {
	return c.CallerAddress
}

// Address returns the contracts address
func (c *Contract) Address() common.Address {
	return c.self
}

// Value returns the contract's value (sent to it from it's caller)
func (c *Contract) Value() *big.Int {
	return c.value
}

func (m *Memory) set(offset, size uint64, value []byte) {
	if size > 0 {
		copy(m.store[offset:offset+size], value)
	}
}

func (m *Memory) set32(offset uint64, val *uint256.Int) {
	b32 := val.Bytes32()
	copy(m.store[offset:], b32[:])
}

func (m *Memory) load(offset, size uint64) *big.Int {
	return new(big.Int).SetBytes(m.store[offset : offset+size])
}

func (m *Memory) size() int {
	fmt.Println("Memory size: ", len(m.store))
	return len(m.store)
}

type Stack struct {
	data []big.Int
}

func newmemory() *Memory {
	return &Memory{store: make([]byte, 0, 1024)}
}

func newstack() *Stack {
	return &Stack{data: make([]big.Int, 0, 1024)}
}

func newContract(tx Transaction) *Contract {
	return &Contract{
		CallerAddress: common.HexToAddress(tx.Origin),
		caller:        common.HexToAddress(tx.From),
		self:          common.HexToAddress(tx.To),
		Input:         common.FromHex(tx.Data),
	}
}

func (st *Stack) push(d *big.Int) {
	st.data = append(st.data, *d)
}

func (st *Stack) pop() (ret big.Int) {
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
	return
}

func (st *Stack) peek() *big.Int {
	return &st.data[st.len()-1]
}

func (st *Stack) dup(n int) {
	st.push(&st.data[st.len()-n])
}

func (st *Stack) swap(n int) {
	st.data[st.len()-n], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-n]
}

func returnStack(st *Stack) []big.Int {
	st.data = st.data[:0]
	return st.data
}

func (st *Stack) len() int {
	return len(st.data)
}

func reverse(numbers []big.Int) []big.Int {
	newNumbers := make([]big.Int, 0, len(numbers))
	for i := len(numbers) - 1; i >= 0; i-- {
		newNumbers = append(newNumbers, numbers[i])
	}
	return newNumbers
}

func evm(code []byte, transaction Transaction, storage map[common.Address]Storage, block Block) []big.Int {
	var stack = newstack()
	var memory = newmemory()
	var contract = newContract(transaction)
	var pc uint64

	for pc < uint64(len(code)) {
		switch code[pc] {
		case 0x00: // STOP
			// break out of the loop
			pc = uint64(len(code))
		case 0x60: // PUSH1
			// push the next byte onto the stack
			stack.push(big.NewInt(int64(code[pc+1])))
			// skip the next byte
			fmt.Println("PUSH1 stack len", stack.len())
			pc++
		case 0x61: // PUSH2
			// push the next 2 bytes onto the stack
			stack.push(big.NewInt(int64(code[pc+1])<<8 | int64(code[pc+2])))
			// skip the next 2 bytes
			pc += 2
		case 0x62: // PUSH3
			// push the next 3 bytes onto the stack
			stack.push(big.NewInt(int64(code[pc+1])<<16 | int64(code[pc+2])<<8 | int64(code[pc+3])))
			// skip the next 3 bytes
			pc += 3
		case 0x73: // PUSH20
			// push the next 20 bytes onto the stack
			stack.push(big.NewInt(0).SetBytes(code[pc+1 : pc+21]))
			// skip the next 20 bytes
			pc += 20
		case 0x7f: // PUSH32
			// push the next 32 bytes onto the stack
			num := uint256.NewInt(0)
			num.SetBytes(code[pc+1 : pc+33])
			stack.push(num.ToBig())
			// skip the next 32 bytes
			pc += 32
		case 0x50: // POP
			// pop the top item off the stack
			stack.pop()
		case 0x01: // ADD
			// pop the top two items off the stack, add them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Add(&a, &b)

			res, _ := uint256.FromBig(z)
			res = res.Mod(res, uint256.NewInt(0).SetUint64(256))
			stack.push(res.ToBig())
		case 0x02: // MUL
			// pop the top two items off the stack, multiply them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Mul(&a, &b)
			z = z.Mod(z, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			stack.push(z)
		case 0x03: // SUB
			// pop the top two items off the stack, subtract them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Sub(&a, &b)
			z = z.Mod(z, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			stack.push(z)
		case 0x04: // DIV
			// pop the top two items off the stack, divide them, and push the result
			a := stack.pop()
			aa, _ := uint256.FromBig(&a)
			b := stack.pop()
			bb, _ := uint256.FromBig(&b)
			z := aa.Div(aa, bb)
			stack.push(z.ToBig())
		case 0x05: // SDIV
			// pop the top two items off the stack, divide them, and push the result
			a := stack.pop()
			aa, _ := uint256.FromBig(&a)
			b := stack.pop()
			bb, _ := uint256.FromBig(&b)
			z := aa.SDiv(aa, bb)
			stack.push(z.ToBig())
		case 0x06: // MOD
			// pop the top two items off the stack, modulo them, and push the result
			a := stack.pop()
			aa, _ := uint256.FromBig(&a)
			b := stack.pop()
			bb, _ := uint256.FromBig(&b)
			z := aa.Mod(aa, bb)
			stack.push(z.ToBig())
		case 0x07: // SMOD
			// pop the top two items off the stack, signed modulo them, and push the result
			a := stack.pop()
			aa, _ := uint256.FromBig(&a)
			b := stack.pop()
			bb, _ := uint256.FromBig(&b)
			z := aa.SMod(aa, bb)
			stack.push(z.ToBig())
		case 0x10: // LT
			// pop the top two items off the stack, compare them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Sub(&a, &b)
			if z.Sign() == -1 {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x11: // GT
			// pop the top two items off the stack, compare them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Sub(&a, &b)
			if z.Sign() == 1 {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x12: // SLT
			//Signed less-than comparison
			a := stack.pop()
			b := stack.pop()
			aa, _ := uint256.FromBig(&a)
			bb, _ := uint256.FromBig(&b)
			if aa.Slt(bb) {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x13: // SGT
			// pop the top two items off the stack, compare them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Sub(&a, &b)
			if z.Sign() == 1 {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x14: // EQ
			// pop the top two items off the stack, compare them, and push the result
			a := stack.pop()
			b := stack.pop()
			if a.Cmp(&b) == 0 {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x15: // ISZERO
			// pop the top item off the stack, compare it to zero, and push the result
			a := stack.pop()
			if a.Cmp(big.NewInt(0)) == 0 {
				stack.push(big.NewInt(1))
			} else {
				stack.push(big.NewInt(0))
			}
		case 0x16: // AND
			// pop the top two items off the stack, bitwise AND them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).And(&a, &b)
			stack.push(z)
		case 0x17: // OR
			// pop the top two items off the stack, bitwise OR them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Or(&a, &b)
			stack.push(z)
		case 0x18: // XOR
			// pop the top two items off the stack, bitwise XOR them, and push the result
			a := stack.pop()
			b := stack.pop()
			z := new(big.Int).Xor(&a, &b)
			stack.push(z)
		case 0x19: // NOT
			// pop the top item off the stack, the bitwise NOT result. Push the result
			a := stack.pop()
			aa, _ := uint256.FromBig(&a)
			z := aa.Not(aa)
			stack.push(z.ToBig())
		case 0x1a: // BYTE
			// pop the top two items off the stack, the bitwise NOT result. Push the result
			a := stack.pop() // index
			b := stack.pop() // value
			aa, _ := uint256.FromBig(&a)
			bb, _ := uint256.FromBig(&b)
			z := bb.Byte(aa)
			stack.push(z.ToBig())
		case 0x80: // DUP1
			// push the first item on the stack onto the stack
			a := stack.peek()
			stack.push(a)
		case 0x82: // DUP3
			// push the third item on the stack onto the stack
			stack.dup(3)
		case 0x90: // SWAP1
			// swap the first and second items on the stack
			stack.swap(2)
		case 0x92: // SWAP3
			// swap the third and fourth items on the stack
			stack.swap(4)
		case 0x58: // PC
			// push the current program counter onto the stack
			stack.push(big.NewInt(int64(pc)))
			// GAS
		case 0x5a: // GAS
			// push the current gas counter onto the stack
			stack.push(MaxUint256.ToBig()) // TODO: hardcoded gas amount
		case 0x56: // JUMP
			// set the program counter to that value
			a := stack.pop()
			pc = uint64(int(a.Int64()))
		case 0x57: // JUMPI
			// pop the top two items off the stack, if the first item is nonzero, set the program counter to the second item
			a := stack.pop()
			b := stack.pop()
			if b.Cmp(big.NewInt(0)) != 0 {
				pc = uint64(int(a.Int64()))
			}
		case 0x51: // MLOAD
			// Load word from memory
			offset := stack.peek()
			memory.load(offset.Uint64(), 32)
			offset.SetBytes(memory.load(offset.Uint64(), 32).Bytes())
			fmt.Println("MLOAD size", memory.size())
		case 0x52: // MSTORE
			// pop the top two items off the stack, and store the second item at the first item
			a := stack.pop() // offset
			b := stack.pop() // value
			bb, _ := uint256.FromBig(&b)
			memory.set(a.Uint64(), uint64(bb.ByteLen()), bb.Bytes())
			fmt.Println("MSTORE stack len", stack.len())
		case 0x53: // MSTORE8
			// pop the top two items off the stack, and store the second item at the first item
			a := stack.pop() // offset
			b := stack.pop() // value
			bb, _ := uint256.FromBig(&b)
			memory.set(a.Uint64(), 1, bb.Bytes())
		case 0x59: // MSIZE
			// push the current size of the memory onto the stack
			// allocate memory with leading zeros

			stack.push(big.NewInt(int64(memory.size())))
		case 0x20: // KECCAK256
			// pop the top two items off the stack, and store the second item at the first item
			a := stack.pop() // offset
			b := stack.pop() // length
			c := memory.load(a.Uint64(), b.Uint64())
			// import github.com/ethereum/go-ethereum/crypto
			d := crypto.Keccak256(c.Bytes())
			stack.push(new(big.Int).SetBytes(d))
		case 0x30: // ADDRESS
			stack.push(new(big.Int).SetBytes(contract.self.Bytes()))
		case 0x31: // BALANCE
			// get the balance of the address on the top of the stack
			a := stack.pop()
			add := common.BytesToAddress(a.Bytes())
			b := storage[add].Balance
			// hex to big int
			res, err := uint256.FromHex(b)
			if err != nil {
				stack.push(big.NewInt(0))
			} else {
				stack.push(res.ToBig())
			}
		case 0x33: // CALLER
			stack.push(new(big.Int).SetBytes(contract.caller.Bytes()))
		case 0x32: // ORIGIN
			stack.push(new(big.Int).SetBytes(common.FromHex(transaction.Origin)))
		case 0x41: // COINBASE
			stack.push(new(big.Int).SetBytes(common.FromHex(block.Coinbase)))
		case 0x42: // TIMESTAMP
			stack.push(new(big.Int).SetBytes(common.FromHex(block.Timestamp)))
		case 0x43: // NUMBER
			stack.push(new(big.Int).SetBytes(common.FromHex(block.Number)))
		case 0x44: // DIFFICULTY
			stack.push(new(big.Int).SetBytes(common.FromHex(block.Difficulty)))
		case 0x45: // GASLIMIT
			stack.push(new(big.Int).SetBytes(common.FromHex(block.GasLimit)))
		case 0x3a: // GASPRICE
			stack.push(new(big.Int).SetBytes(common.FromHex(transaction.Gasprice)))
		case 0x46: // CHAINID
			stack.push(new(big.Int).SetBytes(common.FromHex(block.ChainId)))
		case 0x34: // CALLVALUE
			stack.push(new(big.Int).SetBytes(common.FromHex(transaction.Value)))
		case 0x35: // CALLDATALOAD
			offset := stack.pop()
			data := common.FromHex(transaction.Data)
			head := data[offset.Uint64():]
			// populate tail with zeros
			tail := make([]byte, 32-len(head))
			// concatenate head and tail
			res := append(head, tail...)
			stack.push(new(big.Int).SetBytes(res))
		case 0x36: // CALLDATASIZE
			stack.push(big.NewInt(int64(len(common.FromHex(transaction.Data)))))
		case 0x37: // CALLDATACOPY
			// pop the top three items off the stack, and store the second item at the first item
			a := stack.pop() // offset
			b := stack.pop() // offset
			c := stack.pop() // length
			data := common.FromHex(transaction.Data)
			head := data[b.Uint64() : b.Uint64()+c.Uint64()]
			// populate tail with zeros
			tail := make([]byte, c.Uint64()-uint64(len(head)))
			// concatenate head and tail
			res := append(head, tail...)
			memory.set(a.Uint64(), c.Uint64(), res)
		case 0x38: // CODESIZE
			// push the current size of code onto the stack
			stack.push(big.NewInt(int64(len(code))))
		case 0x39: // CODECOPY
			// Copy code running in current environment to memory
			// destOffset: byte offset in the memory where the result will be copied.
			// offset: byte offset in the code to copy.
			// size: byte size to copy.
			a := stack.pop() // destOffset
			b := stack.pop() // offset
			c := stack.pop() // size
			head := code[b.Uint64() : b.Uint64()+c.Uint64()]
			// populate tail with zeros
			tail := make([]byte, c.Uint64()-uint64(len(head)))
			// concatenate head and tail
			res := append(head, tail...)
			memory.set(a.Uint64(), c.Uint64(), res)
		}
		pc++
	}
	return reverse(stack.data)
}

func main() {
	content, err := ioutil.ReadFile("../evm.json")
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}

	var payload []TestCase
	err = json.Unmarshal(content, &payload)
	if err != nil {
		log.Fatal("Error during json.Unmarshal(): ", err)
	}

	for index, test := range payload {
		fmt.Printf("Test #%v of %v: %v\n", index+1, len(payload), test.Name)

		bin, err := hex.DecodeString(test.Code.Bin)
		if err != nil {
			log.Fatal("Error during hex.DecodeString(): ", err)
		}

		tx := Transaction{
			To:       test.Tx.To,
			From:     test.Tx.From,
			Value:    test.Tx.Value,
			Origin:   test.Tx.Origin,
			Data:     test.Tx.Data,
			Gasprice: test.Tx.Gasprice,
		}

		var expectedStack []big.Int
		for _, s := range test.Expect.Stack {
			i, ok := new(big.Int).SetString(s, 0)
			if !ok {
				log.Fatal("Error during big.Int.SetString(): ", err)
			}
			expectedStack = append(expectedStack, *i)
		}

		// Note: as the test cases get more complex, you'll need to modify this
		// to pass down more arguments to the evm function and return more than
		// just the stack.
		stack := evm(bin, tx, test.State, test.Block)

		match := len(stack) == len(expectedStack)
		if match {
			for i, s := range stack {
				match = match && (s.Cmp(&expectedStack[i]) == 0)
			}
		}

		if !match {
			fmt.Printf("Transaction: %+v\n", test.Tx)
			fmt.Printf("Instructions: \n%v\n", test.Code.Asm)
			fmt.Printf("Expected: %v\n", toStrings(expectedStack))
			fmt.Printf("Got: %v\n\n", toStrings(stack))
			fmt.Printf("Progress: %v/%v\n\n", index, len(payload))
			log.Fatal("Stack mismatch")
		}
	}
}

func toStrings(stack []big.Int) []string {
	var strings []string
	for _, s := range stack {
		strings = append(strings, s.String())
	}
	return strings
}
