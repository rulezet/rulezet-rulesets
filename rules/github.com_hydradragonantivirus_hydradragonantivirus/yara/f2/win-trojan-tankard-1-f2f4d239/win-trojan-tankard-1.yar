rule Win_Trojan_Tankard_1
{
strings:
	$a0 = { fcff740f80fc3d740e3d004b74092eff2e6e00b83412cf }


condition:
	$a0
}