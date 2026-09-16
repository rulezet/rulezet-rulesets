rule Win_Trojan_Worf_4
{
strings:
	$a0 = { 21b8004233c999cd21b440b90300ba78facd21b801572e8b1666fa2e8b0e64fa80e1e080c903cd }


condition:
	$a0
}