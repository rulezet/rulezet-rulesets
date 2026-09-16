rule TrojanDownloader_Win32_BrobanDel_A{
	meta:
		description = "TrojanDownloader:Win32/BrobanDel.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 67 67 63 3a 2f 2f } 		$a_01_1 = {67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d } 		$a_01_2 = {36 41 37 31 37 35 36 35 37 32 37 39 32 45 36 41 37 33 } 		$a_01_3 = {36 39 37 34 36 31 32 45 36 41 37 33 } 		$a_01_4 = {62 69 74 2e 6c 79 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}