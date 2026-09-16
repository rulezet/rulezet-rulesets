rule Trojan_Win32_Emotet_RTH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {37 6b 52 40 58 40 42 75 79 34 37 58 2a 75 5a 6d 54 58 5e 67 35 50 65 2a 3e 47 33 31 77 41 6a 24 42 71 5f 59 69 53 72 46 4a 74 53 36 31 34 51 29 63 26 } 		$a_03_1 = {0d 00 10 00 00 50 8b 55 b0 52 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}