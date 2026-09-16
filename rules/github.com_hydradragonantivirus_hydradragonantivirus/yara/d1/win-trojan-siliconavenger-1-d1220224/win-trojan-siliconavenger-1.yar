rule Win_Trojan_SiliconAvenger_1
{
strings:
	$a0 = { b9e803bd0000befb03cd012e813400004ee2f89ccd019c585b3bc37405909090cd200e171e06fc0e1fb42acd2180fe }


condition:
	$a0
}