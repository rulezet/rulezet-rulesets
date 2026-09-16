rule Trojan_Win64_IcedID_EH_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 68 41 67 44 6c 6f 75 4d 4b 59 } 		$a_01_1 = {61 73 79 75 64 67 6e 61 73 64 79 61 68 64 62 79 75 61 6a 73 61 73 } 		$a_01_2 = {6e 41 71 56 55 5a 42 79 52 55 6a 75 4c } 		$a_01_3 = {74 6f 70 4b 70 69 52 7a 72 4c 74 6e 4d 6f 51 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}