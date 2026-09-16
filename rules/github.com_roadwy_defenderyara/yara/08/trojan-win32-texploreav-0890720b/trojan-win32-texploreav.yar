rule Trojan_Win32_TExploreAV{
	meta:
		description = "Trojan:Win32/TExploreAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 45 78 70 6c 6f 72 65 20 41 56 20 53 45 54 55 50 00 } 		$a_01_1 = {45 78 74 72 6f 79 61 6e 2e 45 58 5f 00 } 		$a_01_2 = {49 4e 44 49 43 45 2e 44 4f 5f 00 } 		$a_01_3 = {55 52 4c 2e 55 52 5f 00 fd 9f 80 00 4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}