rule Trojan_Win64_IcedID_MF_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 20 48 83 c4 18 eb f4 48 83 7c 24 30 00 74 ed 48 8b 04 24 eb 4b 88 08 48 8b 04 24 66 3b ff 74 4b 48 8b 44 24 28 48 89 44 24 08 eb db 48 89 4c 24 08 48 83 ec 18 3a ff 74 0c } 		$a_01_1 = {75 69 66 6e 79 61 73 66 62 6a 61 75 69 6e 79 75 67 61 73 6a 61 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}