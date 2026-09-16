rule Trojan_Win64_Emotet_PBI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 43 00 2e 00 45 00 58 00 45 00 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}