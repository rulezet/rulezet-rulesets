rule Win_Trojan_SdBot_3999
{
strings:
	$a0 = { 946202625644e71f4c3f49f42f9efe7550ddedf4af95fe1da17f07e99f6fdcd347bce39e3942bf1afd6af4db4abfadf4db46bf6df4db4ebfedf41ba2df10fd76d06f873f }


condition:
	$a0
}