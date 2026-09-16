rule Trojan_BAT_Formbook_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 07 61 13 0c 11 0c 11 09 59 } 		$a_81_1 = {31 39 30 33 31 31 30 32 2d 35 61 64 30 2d 34 65 64 35 2d 38 65 61 31 2d 31 32 66 66 31 61 30 38 63 65 37 64 } 		$a_81_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } 		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}