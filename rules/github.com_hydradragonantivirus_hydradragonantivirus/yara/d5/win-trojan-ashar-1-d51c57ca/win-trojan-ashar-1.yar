rule Win_Trojan_Ashar_1
{
strings:
	$a0 = { 4d0081c30002e2f4a113042d0700a313 }


condition:
	$a0
}