rule TrojanDownloader_Win32_Agent_QE_2{
	meta:
		description = "TrojanDownloader:Win32/Agent.QE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 5c 4f 66 66 65 72 42 6f 78 5c 63 6f 6e 66 69 67 2e 78 6d 6c } 		$a_00_1 = {2f 74 72 61 63 6b 73 74 61 74 73 2e 70 68 70 00 69 64 3d 31 26 74 6f 6b 65 6e 3d } 		$a_01_2 = {5c 4f 42 2e 65 78 65 } 		$a_00_3 = {5c 63 6f 75 6e 74 5f 74 6f 74 61 6c 2e 74 78 74 00 68 74 74 70 3a } 		$a_00_4 = {2e 75 7a 34 2e 6e 65 74 2f 6c 6f 67 33 34 37 35 36 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=12
 
}