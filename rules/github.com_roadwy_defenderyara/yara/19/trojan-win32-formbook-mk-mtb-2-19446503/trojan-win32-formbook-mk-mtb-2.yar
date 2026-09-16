rule Trojan_Win32_Formbook_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 83 c4 0c 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 ff 70 04 ff 15 } 		$a_03_1 = {6a 40 68 00 30 00 00 50 57 89 45 f0 ff 15 ?? ?? ?? ?? 57 8b d8 8d 45 d4 50 ff 75 f0 53 56 ff 15 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}