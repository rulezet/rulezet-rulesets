rule Trojan_Win64_Icedid_ER_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 f7 fa 49 ff c0 49 83 de 1e 48 1d 90 17 00 00 4c 13 e8 48 f7 c4 e2 12 00 00 c8 45 00 00 83 04 24 01 8b 04 24 } 		$a_01_1 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}