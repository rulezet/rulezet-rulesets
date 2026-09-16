rule Trojan_Win32_Trickbot_MX_MTB_16{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 ?? 83 c0 01 89 44 24 ?? 8a 54 14 ?? 30 50 ff 83 bc 24 ?? ?? 00 00 00 0f 85 } 		$a_80_1 = {4c 6c 4c 52 4e 4d 3f 50 50 76 45 7a 64 7b 64 72 57 6c 77 53 3f 39 67 7e 58 62 50 63 62 42 31 7e 6f 4b 39 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}