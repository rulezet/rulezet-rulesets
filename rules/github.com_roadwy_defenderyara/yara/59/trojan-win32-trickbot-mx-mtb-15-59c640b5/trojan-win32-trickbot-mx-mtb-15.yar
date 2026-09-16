rule Trojan_Win32_Trickbot_MX_MTB_15{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 9a 1e 00 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 4f } 		$a_80_1 = {33 55 56 6f 5a 50 31 4d 68 76 4a 70 58 74 57 68 58 76 62 4f 42 35 48 72 57 32 4d 75 4e 30 69 57 48 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}