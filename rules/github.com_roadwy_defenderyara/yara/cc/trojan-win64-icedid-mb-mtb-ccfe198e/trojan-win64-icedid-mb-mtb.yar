rule Trojan_Win64_IcedID_MB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 eb d1 eb 22 48 8b 44 24 08 48 ff c0 3a ed 74 56 88 08 48 8b 04 24 3a c9 74 28 48 ff c8 48 89 44 24 30 eb 5a } 		$a_01_1 = {79 67 73 66 61 62 61 79 75 73 66 6a 6e 61 73 66 6b 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}