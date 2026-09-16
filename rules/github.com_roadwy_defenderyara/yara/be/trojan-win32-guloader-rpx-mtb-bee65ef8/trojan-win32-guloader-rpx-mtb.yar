rule Trojan_Win32_Guloader_RPX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6c 65 73 73 6f 72 73 5c 53 57 49 46 54 4e 45 53 53 5c 47 61 74 68 65 72 65 64 5c 53 61 6e 64 76 61 61 6e 65 72 65 6e 2e 6c 6e 6b } 		$a_01_1 = {55 6e 72 65 70 6f 72 74 6f 72 69 61 6c 2e 42 52 4e } 		$a_01_2 = {4f 74 61 72 69 69 64 61 65 2e 48 79 70 } 		$a_01_3 = {69 6e 64 68 6f 6c 64 73 6d 73 73 69 67 65 2e 46 4f 52 } 		$a_01_4 = {55 6e 62 65 64 69 6e 6e 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}