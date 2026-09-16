rule Trojan_Win32_Emotet_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 0c 18 8a 14 32 32 d1 8d 4c 24 ?? 51 88 13 } 		$a_81_1 = {41 54 6e 2a 30 5a 24 57 58 23 30 6f 76 75 4b 4d 7b 38 48 61 75 30 69 33 70 65 57 63 52 6c 33 48 77 43 30 4c 3f 2a 4e 74 53 68 7b 72 70 6b 39 53 50 64 61 30 67 77 7a 77 31 35 67 52 32 64 64 65 61 52 42 31 2a 5a 3f 4e 4a 56 78 6d 50 4b } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}