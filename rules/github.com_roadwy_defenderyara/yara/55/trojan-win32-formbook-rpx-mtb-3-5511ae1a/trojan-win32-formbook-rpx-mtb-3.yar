rule Trojan_Win32_Formbook_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 55 ff 8b 45 d8 03 45 f0 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}