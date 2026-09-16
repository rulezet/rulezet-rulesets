rule Trojan_Win64_BumbleBeeLoader_AG_MSR{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 65 69 31 35 69 } 		$a_01_1 = {4c 69 52 4e 4e 35 46 } 		$a_01_2 = {58 5a 72 45 58 39 32 32 36 31 } 		$a_01_3 = {72 6f 6d 61 6e 74 69 63 20 6c 6f 66 74 79 20 6c 65 67 69 74 69 6d 61 74 65 20 64 69 73 74 72 61 63 74 } 		$a_01_4 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}