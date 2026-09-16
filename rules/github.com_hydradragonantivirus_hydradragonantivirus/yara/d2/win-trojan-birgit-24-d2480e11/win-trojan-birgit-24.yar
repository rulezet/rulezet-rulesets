rule Win_Trojan_Birgit_24
{
strings:
	$a0 = { e2fdba2602ffd2c353ba0e02ffd25bb440b92601ba0001cd2153ba0e02ffd25bc3 }


condition:
	$a0
}