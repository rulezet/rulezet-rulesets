rule Trojan_Win64_IcedID_AJ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 59 37 78 70 51 } 		$a_01_1 = {41 65 34 75 4a 67 } 		$a_01_2 = {42 32 41 67 61 6b 6b 4e 38 } 		$a_01_3 = {42 33 33 44 43 46 73 31 } 		$a_01_4 = {42 48 6f 33 4a 75 6d 47 6e } 		$a_01_5 = {42 59 57 31 52 37 57 55 65 34 31 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}