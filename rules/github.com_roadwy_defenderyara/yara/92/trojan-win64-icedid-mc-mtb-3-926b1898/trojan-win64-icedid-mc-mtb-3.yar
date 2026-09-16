rule Trojan_Win64_IcedID_MC_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 30 48 89 04 24 eb ?? 48 8b 44 24 38 48 89 44 24 08 eb ?? 48 8b 04 24 48 ff c0 eb ?? 8a 09 88 08 eb ?? 48 89 4c 24 08 48 83 ec 28 eb ?? 48 ff c0 48 89 44 24 08 eb } 		$a_01_1 = {42 6e 51 78 74 5a 77 4a 65 6d 79 4f 4d } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}