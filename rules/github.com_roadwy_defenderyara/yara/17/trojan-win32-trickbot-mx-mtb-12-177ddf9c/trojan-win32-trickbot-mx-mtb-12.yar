rule Trojan_Win32_Trickbot_MX_MTB_12{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_80_0 = {78 68 6d 7a 74 46 42 54 50 71 76 69 37 54 79 63 61 5a 6c 48 62 32 32 53 70 6f 47 69 4c 4e 30 36 5a 35 58 6f 6f 57 66 } 		$a_02_1 = {f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff 83 7d ?? 00 75 } 	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}