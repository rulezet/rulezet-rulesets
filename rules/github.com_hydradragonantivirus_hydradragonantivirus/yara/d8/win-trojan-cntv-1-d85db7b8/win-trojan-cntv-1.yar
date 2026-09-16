rule Win_Trojan_CNTV_1
{
strings:
	$a0 = { e80000511e568bf4368b74062ec64426e2eb008cce81c6b2018edebe0000b923051e56813421324646b4f8cb }


condition:
	$a0
}