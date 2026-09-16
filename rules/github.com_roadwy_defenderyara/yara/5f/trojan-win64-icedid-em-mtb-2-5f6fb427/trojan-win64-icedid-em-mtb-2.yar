rule Trojan_Win64_IcedID_EM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 69 70 74 53 74 72 69 6e 67 5f 70 4c 6f 67 41 74 74 72 } 		$a_01_1 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}