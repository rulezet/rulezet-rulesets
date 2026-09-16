rule Trojan_Win64_IcedID_AM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 52 41 4e 38 46 46 4f 47 59 45 } 		$a_01_1 = {41 5a 6e 67 31 76 7a 4e } 		$a_01_2 = {41 76 32 72 43 6b 6c 79 79 7a 75 } 		$a_01_3 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 } 		$a_01_4 = {52 61 73 44 69 61 6c 57 } 		$a_01_5 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 57 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}