rule Trojan_Win32_Trickbot_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 85 ?? ?? ?? ?? 8d 7f 01 8a 8c 15 ?? ?? ?? ?? 30 4f ff 4e } 		$a_80_1 = {79 4b 61 74 42 62 67 44 77 55 36 78 79 6c 68 51 6d 56 68 46 50 65 73 79 36 64 4c 4f 7a 4c 76 64 56 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}