rule Trojan_Win64_Tedy_PGT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 41 00 70 00 70 } 		$a_01_1 = {30 01 48 8d 49 01 48 83 eb 01 75 f4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}