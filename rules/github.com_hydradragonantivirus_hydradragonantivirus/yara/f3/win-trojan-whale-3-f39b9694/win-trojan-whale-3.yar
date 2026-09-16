rule Win_Trojan_Whale_3
{
strings:
	$a0 = { e828008ccb538cdb1f81c361dce81e00 }


condition:
	$a0
}