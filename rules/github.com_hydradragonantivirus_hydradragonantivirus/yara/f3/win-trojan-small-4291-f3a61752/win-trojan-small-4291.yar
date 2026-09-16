rule Win_Trojan_Small_4291
{
strings:
	$a0 = { 60668bcb22c1c0e903e80a0000006651eb049502964e665b5b8bcb83c10a515b }


condition:
	$a0
}