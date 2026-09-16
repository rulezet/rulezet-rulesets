rule Win_Trojan_Hi_4
{
strings:
	$a0 = { 50e800005d33c08ed883ed06813e6401d32e75190e1f8ccb3e2b9e8a003e039e8e003e8b8e8c00581f075351cbc7 }


condition:
	$a0
}