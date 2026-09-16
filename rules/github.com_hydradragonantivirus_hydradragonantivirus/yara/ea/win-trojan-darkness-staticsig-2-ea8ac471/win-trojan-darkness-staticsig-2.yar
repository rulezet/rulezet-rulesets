rule Win_Trojan_Darkness_staticsig_2
{
strings:
	$a0 = { cca0e8d504d5869acf66248f928c12fa2c }


condition:
	$a0
}