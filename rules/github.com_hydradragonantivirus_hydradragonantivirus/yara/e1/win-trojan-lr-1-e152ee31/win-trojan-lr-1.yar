rule Win_Trojan_LR_1
{
strings:
	$a0 = { ea8cd3f35dae1b22464e428188677620ff5f788481266f59b88f32b7581dd28995bbf953a728ac2c }


condition:
	$a0
}