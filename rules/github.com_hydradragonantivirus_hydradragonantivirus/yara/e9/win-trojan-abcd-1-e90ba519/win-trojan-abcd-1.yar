rule Win_Trojan_ABCD_1
{
strings:
	$a0 = { 02be0305bf0301b93a00f3a4be0001bf0005b95201f3a48b1675018b0e7301bb0005b80103cd13 }


condition:
	$a0
}