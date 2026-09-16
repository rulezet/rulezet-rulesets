rule Trojan_Win64_IcedID_MZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 09 88 08 eb 18 48 ff c0 48 89 44 24 10 eb 5b eb 6e 48 8b 44 24 08 48 8b 4c 24 10 eb e2 48 8b 44 24 08 48 ff c0 eb } 		$a_01_1 = {4e 6a 61 73 64 6b 61 73 6a 64 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}