rule Trojan_Win64_Cobaltstrike_AG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 5c 43 61 6c 6c 44 4c 4c 44 79 6e 61 6d 69 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 65 73 74 44 4c 4c 2e 70 64 62 } 		$a_01_1 = {74 65 73 74 44 4c 4c 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}