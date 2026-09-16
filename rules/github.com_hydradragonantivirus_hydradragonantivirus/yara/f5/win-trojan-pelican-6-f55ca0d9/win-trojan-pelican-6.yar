rule Win_Trojan_Pelican_6
{
strings:
	$a0 = { 20005059b801fa9387d987cab9455987cb9392cd16b9c601bb2c002e8107000083c30283e90175f3 }


condition:
	$a0
}