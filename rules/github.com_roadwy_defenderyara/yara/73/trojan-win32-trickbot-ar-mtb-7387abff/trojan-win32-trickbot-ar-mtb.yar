rule Trojan_Win32_Trickbot_AR_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c1 0f b7 0f 8d 70 bf 66 83 fe 19 77 03 83 c0 20 8d 71 bf 66 83 fe 19 77 03 83 c1 20 66 3b c1 } 		$a_01_1 = {8b 34 b2 8b 45 08 03 f1 8a 1e 3a 18 75 18 84 db 74 10 8a 5e 01 } 		$a_01_2 = {8b 44 24 14 8d 0c 03 8b 44 24 1c 88 1c 08 8b c3 99 f7 7d 14 8b 45 10 43 8a 04 02 88 01 3b de } 		$a_81_3 = {63 3a 5c 55 73 65 72 73 5c 4d 72 2e 41 6e 64 65 72 73 6f 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 41 6e 64 65 72 73 6f 6e 5c 52 65 6c 65 61 73 65 5c 41 6e 64 65 72 73 6f 6e 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_81_3  & 1)*10) >=15
 
}