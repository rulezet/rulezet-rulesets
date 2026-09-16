rule Win_Trojan_Monster_31
{
strings:
	$a0 = { 01bede2cfc300446e2fb25cdcd934e23ce0b89c13326cd0b89c1cd2544cc47492ccc6fcdcc46492fcc6ecccc }


condition:
	$a0
}