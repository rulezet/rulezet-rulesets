rule Trojan_Win32_Emotet_RTA_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0b c8 51 8b 45 ?? 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45 ?? e9 } 		$a_80_1 = {4f 51 5a 58 4d 4a 64 42 7a 31 47 2b 6f 40 64 2b 63 23 7a 38 4f 41 48 58 24 28 31 2a 53 37 30 6f 33 37 56 49 44 75 76 6f 24 3e 50 54 31 29 76 70 65 29 74 68 6c 40 6e 72 41 47 5a 78 47 74 4c 41 73 65 42 59 6d 68 37 } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}