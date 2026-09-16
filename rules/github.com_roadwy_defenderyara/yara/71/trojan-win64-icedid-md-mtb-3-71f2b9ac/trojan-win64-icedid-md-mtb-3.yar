rule Trojan_Win64_IcedID_MD_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 08 48 8b 44 24 30 eb 00 48 ff c8 48 89 44 24 30 eb 92 eb 9e 48 8b 44 24 28 48 89 44 24 08 eb 84 48 8b 44 24 20 48 89 04 24 66 3b ed 74 e6 88 08 48 8b 04 24 66 3b ff 74 9d } 		$a_01_1 = {68 69 61 75 73 66 62 75 73 6a 61 66 6b 68 79 61 73 6a 66 6b } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}