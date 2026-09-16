rule Win_Trojan_Pelican_1
{
strings:
	$a0 = { 20005059b801fa9387d987cab9455987cb9392cd16b9b201bb2c002e8107000083c30283e90175f3 }


condition:
	$a0
}