rule Win_Trojan_Small_4555
{
strings:
	$a0 = { 81c0be4c400068452345006852329800 }


condition:
	$a0
}