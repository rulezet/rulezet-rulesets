rule anti_debug__INT_3_s_with_SoftICE_s_I3HERE__8_byt_20_
{
strings:
	$a0 = { 66be474666bf4d4a0e1f66b8110966ba0e00cd03 }

condition:
	$a0
}