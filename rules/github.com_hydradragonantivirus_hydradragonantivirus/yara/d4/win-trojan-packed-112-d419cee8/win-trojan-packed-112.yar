rule Win_Trojan_Packed_112
{
strings:
	$a0 = { 90905589e56aff906a006a00648b0500 }


condition:
	$a0
}