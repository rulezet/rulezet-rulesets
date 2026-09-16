rule Win_Trojan_B_72
{
strings:
	$a0 = { 817dff0e1304e2faa11304c1e0062dc0078ec00e1fb90002be007c8bfef3a406b8717c50cb }


condition:
	$a0
}