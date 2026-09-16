rule Trojan_Win64_IcedID_MY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 eb 89 c8 c1 f8 ?? c1 fa ?? 29 c2 89 c8 44 8d 04 d2 45 01 c0 44 29 c0 4c 63 c0 46 0f b6 04 06 45 32 04 09 45 88 04 0a 44 8d 41 01 48 83 c1 01 44 39 44 24 2c 77 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}