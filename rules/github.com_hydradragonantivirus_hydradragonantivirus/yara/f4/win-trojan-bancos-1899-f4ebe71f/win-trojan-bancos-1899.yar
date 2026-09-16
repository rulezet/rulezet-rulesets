rule Win_Trojan_Bancos_1899
{
strings:
	$a0 = { e00283a9685fdea995aa2aede969d78fc233ed9fb9f90d45b721cc00609e552cec4520fa061c3d554b61c280963b1608fdf6ab44bd936ab629630ec35379a2c1b4de737183f1 }


condition:
	$a0
}