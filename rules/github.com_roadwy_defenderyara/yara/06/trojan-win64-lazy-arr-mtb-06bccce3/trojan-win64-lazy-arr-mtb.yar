rule Trojan_Win64_Lazy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 33 7a 77 33 76 66 31 62 6e 38 4a 61 51 79 31 } 		$a_81_1 = {4c 4c 49 65 6c 44 6d 45 53 33 31 4b 53 68 41 41 } 	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*5) >=20
 
}