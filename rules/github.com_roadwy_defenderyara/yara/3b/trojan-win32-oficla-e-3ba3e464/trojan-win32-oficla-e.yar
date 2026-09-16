rule Trojan_Win32_Oficla_E{
	meta:
		description = "Trojan:Win32/Oficla.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 30 29 18 e8 ?? ?? ?? ?? 8d 95 ?? ?? ff ff b9 20 00 00 00 } 		$a_03_1 = {ff 53 04 8d 93 ?? ?? 00 00 83 ec 08 89 ?? ?? ff d0 83 e8 01 83 ec 04 83 f8 01 76 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}