rule Trojan_Win64_IcedID_MD_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb e9 48 8b 44 24 40 48 ff c8 eb 28 48 8b 04 24 48 ff c0 eb e2 4c 89 44 24 18 48 89 54 24 10 eb bf 48 8b 44 24 38 48 89 44 24 08 eb 21 8a 09 88 08 eb d9 } 		$a_01_1 = {69 66 78 64 64 70 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 45 70 48 55 48 55 4d 46 45 69 67 48 6f 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}