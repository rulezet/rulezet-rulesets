rule Trojan_Win32_Formbook_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 88 45 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 4d fe 33 c1 8b 4d f8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}