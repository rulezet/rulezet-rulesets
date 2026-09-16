rule Trojan_Win32_Emotet_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 } 		$a_80_1 = {36 58 66 75 41 66 6a 4b 74 46 72 57 39 4a 70 58 30 53 35 43 33 78 55 34 58 54 70 62 6c 7a 4c 68 45 70 61 58 57 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}