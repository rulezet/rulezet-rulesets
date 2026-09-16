rule Trojan_Win32_Emotet_AG_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 33 2e 65 78 65 } 		$a_01_1 = {7a 63 44 44 46 76 68 6a 6e 6d 55 66 64 53 41 77 4b 4d 4e 62 } 		$a_01_2 = {41 63 74 78 } 		$a_01_3 = {43 68 6f 6f 73 65 20 61 20 46 6f 6c 64 65 72 20 6f 72 20 43 72 65 61 74 65 20 61 20 4e 65 77 20 4f 6e 65 } 		$a_01_4 = {4e 6f 20 53 65 6c 65 63 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}