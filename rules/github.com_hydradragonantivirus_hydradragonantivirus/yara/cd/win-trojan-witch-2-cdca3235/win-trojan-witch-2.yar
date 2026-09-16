rule Win_Trojan_Witch_2
{
strings:
	$a0 = { ec480644445833c283c27f50e2f5 }


condition:
	$a0
}