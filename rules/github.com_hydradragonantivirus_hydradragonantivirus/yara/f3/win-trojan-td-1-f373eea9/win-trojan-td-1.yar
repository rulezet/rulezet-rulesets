rule Win_Trojan_TD_1
{
strings:
	$a0 = { 8ed0fb8ed8832e130404a11304c1e0068ec00e1fb9000233ffbe007cf3a406687a00cb5444 }


condition:
	$a0
}