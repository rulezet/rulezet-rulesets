rule TrojanDownloader_Win32_Dofoil_AB_2{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 73 6d 72 63 61 65 41 } 		$a_01_1 = {6d 6e 48 31 32 32 } 		$a_01_2 = {54 6b 6e 6a 51 74 33 34 2d 66 73 65 2b 64 67 66 2e 31 31 31 68 31 32 } 		$a_01_3 = {67 69 70 4f 6f 5a 61 55 79 69 } 		$a_01_4 = {56 51 53 6f 6c 4c 55 62 69 4a } 		$a_01_5 = {39 45 65 74 6d 63 6d 70 69 5f 74 68 78 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}