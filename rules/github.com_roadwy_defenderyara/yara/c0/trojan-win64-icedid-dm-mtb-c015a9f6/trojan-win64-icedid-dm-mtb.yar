rule Trojan_Win64_IcedID_DM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0 } 		$a_03_1 = {41 8b c0 41 ff c0 83 e0 ?? 42 8a 44 20 ?? 30 01 48 ff c1 44 3b c3 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}