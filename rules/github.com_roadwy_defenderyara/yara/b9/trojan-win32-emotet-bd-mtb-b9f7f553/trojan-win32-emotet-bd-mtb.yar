rule Trojan_Win32_Emotet_BD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 c3 } 		$a_02_1 = {88 03 8b 44 24 ?? 83 c4 08 43 48 89 5c 24 ?? 89 44 24 ?? 0f 85 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}