rule Win_Trojan_Agent_32699
{
strings:
	$a0 = { ca2b5befdca7b8add4ceca362e70c3de3fabfa80f4f1cb65714118983705f5a3eb546f1ba3b49d29c27bf87fd9b1bd47ce8cd4e0baa85ab413e4bb12a981778fffbd42e2 }


condition:
	$a0
}