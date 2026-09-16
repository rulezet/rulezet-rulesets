rule Trojan_Win32_Emotet_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 14 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f 85 } 		$a_80_1 = {43 6b 77 34 63 71 4b 37 67 64 36 4a 35 6c 76 34 4a 42 5a 39 33 4d 50 73 7a 74 72 30 66 68 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}