rule Trojan_Win64_Icedid_ER_MTB_7{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 41 76 68 63 70 56 41 47 68 } 		$a_01_1 = {61 47 5a 34 54 49 77 6b 75 34 77 50 53 37 48 42 64 59 6d 33 5a 37 73 64 36 72 62 59 48 36 39 6a 45 } 		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_3 = {52 41 43 6d 75 69 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}