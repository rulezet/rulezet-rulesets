rule Win_Trojan_VSP3_1
{
strings:
	$a0 = { 33c08ec026813e8400ab057438be0001bf3405b9bb01fcf3a4fa26a1840026a3e20626a1860026a3e40626c7068400 }


condition:
	$a0
}