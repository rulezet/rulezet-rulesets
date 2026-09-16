rule TrojanDownloader_Win64_Agent_AMTB{
	meta:
		description = "TrojanDownloader:Win64/Agent!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 73 68 69 65 6c 64 67 75 61 72 64 76 70 6e 2e 70 72 6f 2f 76 70 6e 2f 75 70 64 61 74 65 73 2f 73 74 61 62 6c 65 2e 7a 69 70 } 		$a_80_1 = {51 28 52 28 53 28 54 31 55 31 56 44 57 45 58 45 59 45 5a 45 5b 45 5c 45 5d 4a 5e 4a 5f 4a 60 4a 61 4a 62 4a 63 4a 64 4a 65 4a 66 4a 67 4a 68 4a } 	condition:
		((#a_80_0  & 1)*6+(#a_80_1  & 1)*6) >=6
 
}