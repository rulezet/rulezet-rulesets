rule Trojan_Win32_Redline_GNI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d6 80 04 2f ?? 68 } 		$a_03_1 = {6a 00 ff d6 80 34 2f ?? 68 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}