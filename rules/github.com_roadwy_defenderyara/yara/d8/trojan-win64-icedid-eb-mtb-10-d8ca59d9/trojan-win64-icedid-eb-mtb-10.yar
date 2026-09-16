rule Trojan_Win64_IcedID_EB_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 61 69 73 64 6e 68 61 73 64 69 61 6b 6a 73 64 6e 61 69 73 73 } 		$a_01_1 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 57 } 		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}