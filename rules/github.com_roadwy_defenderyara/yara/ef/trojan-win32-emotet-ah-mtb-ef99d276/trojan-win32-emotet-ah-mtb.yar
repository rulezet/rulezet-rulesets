rule Trojan_Win32_Emotet_AH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8d 04 bf 2b d0 8b 44 24 ?? 03 d1 8b 0d ?? ?? ?? ?? 0f b6 14 8a 30 10 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82 } 		$a_01_1 = {74 45 26 38 61 28 3e 24 69 66 69 39 3c 69 72 26 6e 2b 33 47 4b 69 48 32 54 59 6f 24 77 6b 52 6d 52 39 44 70 42 50 5a 75 4d 6e 37 41 69 6b 47 41 24 74 3f 71 4c 41 5f 4c 37 4e 5a 5a 78 23 4d 71 35 2b 24 72 46 36 41 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}