rule Trojan_Win64_IcedID_DA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0 ?? 75 } 		$a_03_1 = {8b c2 ff c2 83 e0 ?? 42 8a 44 20 ?? 30 01 48 ff c1 3b d3 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}