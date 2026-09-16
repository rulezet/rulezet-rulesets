rule Trojan_Win32_Redline_GNV_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 4d 02 c1 e1 10 0f be 45 01 c1 e0 08 33 c8 0f be 45 00 33 c1 } 		$a_01_1 = {8b 44 24 24 8b 54 24 18 40 89 44 24 24 3b 44 24 3c } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}