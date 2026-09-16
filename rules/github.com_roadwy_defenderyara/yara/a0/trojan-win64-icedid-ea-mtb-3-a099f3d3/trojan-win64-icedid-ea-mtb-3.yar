rule Trojan_Win64_IcedID_EA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb 59 80 44 24 42 24 c6 44 24 43 4d eb dc 48 81 ec 88 08 00 00 c6 44 24 40 76 eb 0c 80 44 24 45 43 c6 44 24 46 0d eb 0c 80 44 24 40 00 c6 44 24 41 5b eb 1b } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}