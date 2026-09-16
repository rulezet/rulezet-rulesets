rule Win_Trojan_Whale_4
{
strings:
	$a0 = { e829008ccb538cdb1f81c361dce81f00 }


condition:
	$a0
}