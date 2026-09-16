rule Trojan_Win32_Nitol_RJ_MTB{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 79 2e 6c 6e 6b } 		$a_01_1 = {46 3a 5c 68 61 63 6b 73 68 65 6e 2e 65 78 65 } 		$a_01_2 = {3a 39 38 37 34 2f 41 6e 79 44 65 73 6b 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}