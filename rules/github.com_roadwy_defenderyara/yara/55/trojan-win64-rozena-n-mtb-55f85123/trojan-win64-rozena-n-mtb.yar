rule Trojan_Win64_Rozena_N_MTB{
	meta:
		description = "Trojan:Win64/Rozena.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 4c 24 30 4c 89 4c ca 18 eb ?? 4c 8b 4c 24 30 e8 68 6e 04 00 4c 8b 4c 24 38 } 		$a_01_1 = {59 69 68 73 69 77 65 69 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}