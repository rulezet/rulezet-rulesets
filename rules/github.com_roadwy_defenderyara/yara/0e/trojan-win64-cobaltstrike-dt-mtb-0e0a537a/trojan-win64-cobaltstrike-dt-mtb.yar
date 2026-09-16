rule Trojan_Win64_Cobaltstrike_DT_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d 35 48 8b 44 24 08 0f b6 00 33 44 24 38 48 8b 4c 24 08 88 01 48 8b 44 24 08 0f b6 00 2b 44 24 30 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 ff c0 48 89 44 24 08 eb } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}