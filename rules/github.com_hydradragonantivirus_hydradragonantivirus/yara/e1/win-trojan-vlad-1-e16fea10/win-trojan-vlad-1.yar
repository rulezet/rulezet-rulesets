rule Win_Trojan_Vlad_1
{
strings:
	$a0 = { 3c4f740d583dfeca750ab80df0cfe9cc01e99b01e989 }


condition:
	$a0
}