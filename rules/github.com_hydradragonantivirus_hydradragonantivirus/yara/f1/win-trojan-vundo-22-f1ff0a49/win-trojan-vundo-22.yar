rule Win_Trojan_Vundo_22
{
strings:
	$a0 = { 60e8521a0000a059 }


condition:
	$a0
}