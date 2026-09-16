rule Trojan_Win32_Nitol_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Nitol.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 35 00 34 00 2e 00 32 00 31 00 31 00 2e 00 31 00 34 00 2e 00 39 00 31 00 2f 00 77 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } 		$a_01_1 = {57 69 6e 64 6f 77 73 50 72 6f 6a 65 63 74 38 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}