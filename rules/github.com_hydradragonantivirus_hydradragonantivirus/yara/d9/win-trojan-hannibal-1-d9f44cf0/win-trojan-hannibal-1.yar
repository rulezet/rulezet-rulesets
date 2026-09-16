rule Win_Trojan_Hannibal_1
{
strings:
	$a0 = { fc1274bb80fc4e74b980fc4f74b42e803e8301007403e9 }


condition:
	$a0
}