rule Win_Trojan_DVLCrash_1
{
strings:
	$a0 = { 406563686f20633a5c6e756c5c6e756c3e633a5c6175746f657865632e626174 }


condition:
	$a0
}