rule Trojan_Win64_IcedID_H_MTB{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 ff c0 66 3b ff 74 4c 88 08 48 8b 04 24 66 3b d2 74 1a 48 8b 44 24 20 48 89 04 24 66 3b c0 74 3f 48 8b 4c 24 08 8a 09 66 3b ff 74 db } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}