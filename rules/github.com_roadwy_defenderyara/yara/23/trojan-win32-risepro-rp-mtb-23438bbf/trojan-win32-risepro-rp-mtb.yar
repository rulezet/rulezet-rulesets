rule Trojan_Win32_RisePro_RP_MTB{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } 		$a_01_1 = {53 74 65 61 6c 65 72 43 6c 69 65 6e 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}