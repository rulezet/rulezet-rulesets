rule Win_Trojan_Mannequin_1
{
strings:
	$a0 = { 51535032c01e078bfab94100fcf2ae83ef0c8bf70e07bf }


condition:
	$a0
}