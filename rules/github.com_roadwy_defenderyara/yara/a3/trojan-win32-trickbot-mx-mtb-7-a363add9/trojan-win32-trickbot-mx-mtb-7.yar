rule Trojan_Win32_Trickbot_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8a 03 83 c4 0c 8a 54 14 ?? 32 c2 88 03 43 4d } 		$a_80_1 = {4d 43 64 4d 31 41 77 7c 32 53 61 47 32 72 64 47 7a 79 49 33 55 37 24 4b 25 76 65 74 75 69 56 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}