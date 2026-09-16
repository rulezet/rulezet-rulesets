rule Trojan_Win32_Emotet_PBB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8a 14 2b 32 c2 88 03 } 		$a_81_1 = {4a 65 53 7e 7e 50 63 43 73 43 71 2a 45 7b 69 70 3f 52 64 75 51 78 39 79 59 5a 77 79 37 72 33 63 54 33 59 55 5a 6a 7e 78 61 37 31 61 53 36 59 6b 78 7c 65 44 38 4d 40 56 74 62 79 48 34 4f 4e 7e 77 51 35 76 6a 46 58 63 32 70 62 31 6b 24 57 4c 6d 70 69 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}