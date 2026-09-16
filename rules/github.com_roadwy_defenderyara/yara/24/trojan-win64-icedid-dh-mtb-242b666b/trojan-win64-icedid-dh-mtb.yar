rule Trojan_Win64_IcedID_DH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 ?? 66 3b db 74 ?? 33 c8 8b c1 3a ed 74 ?? 48 63 0c 24 } 		$a_03_1 = {48 8b 4c 24 ?? 8a 09 3a c9 74 ?? 48 ff c0 48 89 04 24 3a ed 74 ?? 48 ff c8 48 89 44 24 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}