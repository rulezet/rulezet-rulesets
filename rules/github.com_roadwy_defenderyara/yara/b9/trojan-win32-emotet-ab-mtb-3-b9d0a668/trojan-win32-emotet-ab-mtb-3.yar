rule Trojan_Win32_Emotet_AB_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 2c 8d 04 0a 99 b9 69 7a 00 00 f7 f9 8b 6c 24 54 2b 54 24 14 8b ca 8b 54 24 30 0f b6 } 		$a_01_1 = {99 bd 69 7a 00 00 f7 fd 8b 44 24 54 8b 6c 24 18 83 c5 01 89 6c 24 18 03 d7 03 d6 0f b6 14 02 } 		$a_01_2 = {70 21 63 21 58 38 3c 30 61 69 52 31 3e 66 6b 64 79 6d 45 3c 58 21 21 78 66 64 74 5a 3f 3c 2a 26 6e 4a 78 52 5a 7a 39 56 6f 79 21 26 71 33 2a 49 54 6b 46 35 37 72 40 5f 45 61 43 4c 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}