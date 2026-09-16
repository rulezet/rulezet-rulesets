rule Win_Trojan_Small_4261
{
strings:
	$a0 = { 55545db8c81cd9d98d80382727[0-250]608d5c24208b5c2300[0-10]eb1069db }


condition:
	$a0
}