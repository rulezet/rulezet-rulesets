rule Trojan_Win32_TrickBotCrypt_EH_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 f8 8a c1 f6 eb b1 1f f6 e9 8a 0c 32 b2 1f 2a c8 a0 ?? ?? ?? ?? f6 ea 02 c8 2a 0d ?? ?? ?? ?? 30 0f 90 09 06 00 8b 45 ?? 8b 7d } 		$a_81_1 = {4f 6c 32 41 23 32 3e 66 35 76 35 4c 38 6c 46 26 44 51 52 26 3f 38 4b 4b 4f 78 72 35 4a 30 2b 33 4d 3f 78 33 4a 75 45 31 2b 56 21 38 37 37 3e 5f 68 24 3e 66 34 69 5f 30 77 38 59 34 31 68 3e 63 38 6d 44 62 44 71 4c 44 71 70 4d 66 34 52 34 69 38 48 2a } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}