rule Win_Trojan_VGEN_78
{
strings:
	$a0 = { 5107be85690bd02e8bd33e8bcebb6303b9bc56b92936fd26298c0f9ffc909026318c0f9fd79026018c0f9f90268b }


condition:
	$a0
}