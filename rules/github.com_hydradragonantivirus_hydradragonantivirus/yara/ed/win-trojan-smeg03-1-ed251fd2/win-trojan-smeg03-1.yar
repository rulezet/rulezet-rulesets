rule Win_Trojan_Smeg03_1
{
strings:
	$a0 = { fcad93ac5053e86f01e8030032c0cf5ab82425cd2106b42fcd21 }


condition:
	$a0
}