rule Trojan_Win32_Emotet_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {47 5f 55 37 66 52 5f 74 4e 3e 51 33 6b 30 53 5f 64 61 74 34 50 2a 57 59 3c 4a 73 38 2b 29 43 2a 21 64 3f 76 21 71 21 3f 4f 5f 36 75 56 78 63 31 35 74 3c 3e 44 56 25 72 40 37 4a 55 66 79 78 32 79 63 62 43 78 4b 40 6c 64 58 26 43 23 4b 29 3f 45 3c 40 59 75 2b 36 53 6c 4b 24 49 72 } 		$a_03_1 = {68 00 30 00 00 8b 45 b0 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}