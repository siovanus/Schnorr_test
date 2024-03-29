package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// 组合算法(从nums中取出m个数)
func combineResult(n int, m int) [][]int {
	if m < 1 || m > n {
		fmt.Println("Illegal argument. Param m must between 1 and len(nums).")
		return [][]int{}
	}
	//保存最终结果的数组，总数直接通过数学公式计算
	result := make([][]int, 0, mathCombination(n, m))
	//保存每一个组合的索引的数组，1表示选中，0表示未选中
	indexs := make([]int, n)
	for i := 0; i < n; i++ {
		if i < m {
			indexs[i] = 1
		} else {
			indexs[i] = 0
		}
	}
	//第一个结果
	result = addTo(result, indexs)
	for {
		find := false
		//每次循环将第一次出现的 1 0 改为 0 1，同时将左侧的1移动到最左侧
		for i := 0; i < n-1; i++ {
			if indexs[i] == 1 && indexs[i+1] == 0 {
				find = true
				indexs[i], indexs[i+1] = 0, 1
				if i > 1 {
					moveOneToLeft(indexs[:i])
				}
				result = addTo(result, indexs)
				break
			}
		}
		//本次循环没有找到 1 0 ，说明已经取到了最后一种情况
		if !find {
			break
		}
	}
	return result
}

// 将ele复制后添加到arr中，返回新的数组
func addTo(arr [][]int, ele []int) [][]int {
	newEle := make([]int, len(ele))
	copy(newEle, ele)
	arr = append(arr, newEle)
	return arr
}
func moveOneToLeft(leftNums []int) {
	//计算有几个1
	sum := 0
	for i := 0; i < len(leftNums); i++ {
		if leftNums[i] == 1 {
			sum++
		}
	}
	//将前sum个改为1，之后的改为0
	for i := 0; i < len(leftNums); i++ {
		if i < sum {
			leftNums[i] = 1
		} else {
			leftNums[i] = 0
		}
	}
}

// 根据索引号数组得到元素数组
func findByIndexs(elems []*btcec.PublicKey, indexs [][]int) []*Comb {
	if len(indexs) == 0 {
		panic("length of keys is 0")
	}
	result := make([]*Comb, len(indexs))
	for i, v := range indexs {
		comb := &Comb{
			Pubs: make([]*btcec.PublicKey, 0),
		}
		for j, v2 := range v {
			if v2 == 1 {
				comb.Pubs = append(comb.Pubs, elems[j])
				comb.Indexs = v
			}
		}
		result[i] = comb
	}
	return result
}

// 数学方法计算组合数(从n中取m个数)
func mathCombination(n int, m int) int {
	return factorial(n) / (factorial(n-m) * factorial(m))
}

// 阶乘
func factorial(n int) int {
	result := 1
	for i := 2; i <= n; i++ {
		result *= i
	}
	return result
}
