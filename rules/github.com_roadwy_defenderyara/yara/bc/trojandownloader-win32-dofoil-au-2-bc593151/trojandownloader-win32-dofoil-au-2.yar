rule TrojanDownloader_Win32_Dofoil_AU_2{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 7a 00 7a 00 7a 00 69 00 70 00 2e 00 74 00 69 00 6e 00 79 00 2e 00 75 00 73 00 2f 00 6d 00 61 00 78 00 30 00 32 00 31 00 35 00 34 00 61 00 } 		$a_01_1 = {43 00 6b 00 70 00 67 00 61 00 75 00 69 00 64 00 71 00 7a 00 6b 00 68 00 70 00 69 00 6e 00 79 00 65 00 70 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}