rule TrojanDownloader_Win32_Agent_QE{
	meta:
		description = "TrojanDownloader:Win32/Agent.QE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 69 6e 65 74 63 2e 64 6c 6c } 		$a_02_1 = {2e 77 67 65 74 74 2e 63 6f 2e 63 63 2f [0-10] 2e 70 68 70 } 		$a_00_2 = {74 6f 6b 65 6e 3d } 		$a_00_3 = {2f 53 49 4c 45 4e 54 } 		$a_00_4 = {2e 65 78 65 22 20 2f 53 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}