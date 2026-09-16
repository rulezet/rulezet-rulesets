rule Trojan_Win64_IcedID_EH_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 69 61 73 67 79 66 61 62 68 73 66 79 61 73 6e 6a 61 75 73 61 73 } 		$a_01_1 = {43 72 65 61 74 65 53 65 6d 61 70 68 6f 72 65 57 } 		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } 		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}