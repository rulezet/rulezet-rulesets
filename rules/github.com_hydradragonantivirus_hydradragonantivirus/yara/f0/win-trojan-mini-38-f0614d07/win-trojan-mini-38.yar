rule Win_Trojan_Mini_38
{
strings:
	$a0 = { 06b440ba0001b9720b2e8b1eb306e8eefc3d720b741d2e8b1eb106b43ee8dffc }


condition:
	$a0
}