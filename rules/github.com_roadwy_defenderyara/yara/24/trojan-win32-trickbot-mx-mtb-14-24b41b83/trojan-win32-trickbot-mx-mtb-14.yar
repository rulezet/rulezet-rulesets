rule Trojan_Win32_Trickbot_MX_MTB_14{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ff 8b 8d ?? ?? ?? ?? 4f 75 } 		$a_80_1 = {7a 73 77 4b 4e 46 34 67 6e 64 31 30 4f 74 4a 6b 66 53 75 35 72 63 6a 6c 4a 46 76 72 72 6c 54 63 57 78 71 77 55 43 79 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}