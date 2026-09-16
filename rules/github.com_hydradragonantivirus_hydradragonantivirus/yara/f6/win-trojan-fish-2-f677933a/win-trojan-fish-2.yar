rule Win_Trojan_Fish_2
{
strings:
	$a0 = { 5b81eba90db9580d2e80371543e2f92efe8fb3007403e960f4c3 }


condition:
	$a0
}