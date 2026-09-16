rule Trojan_AndroidOS_Boxer_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 6f 66 74 77 61 72 65 2e 61 64 75 6c 74 } 		$a_00_1 = {4b 45 59 5f 57 41 53 5f 4f 50 45 4e 45 44 } 		$a_00_2 = {55 53 53 44 45 78 74 4e 65 74 53 76 63 } 		$a_00_3 = {31 37 38 35 33 33 31 37 36 38 32 36 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}