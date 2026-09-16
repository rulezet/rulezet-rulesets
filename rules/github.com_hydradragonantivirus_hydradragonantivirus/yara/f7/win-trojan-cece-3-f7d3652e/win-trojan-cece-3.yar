rule Win_Trojan_CeCe_3
{
strings:
	$a0 = { 29cac9ce35e7cc7f9b4bb263ea6c1d33a7469c10b72aee398bdbf2c7790a5a87399e4e41c136e3a4 }


condition:
	$a0
}