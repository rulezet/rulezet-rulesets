rule Win_Trojan_Trojan_260
{
strings:
	$a0 = { 83ed09be200103f5fcb6 }


condition:
	$a0
}