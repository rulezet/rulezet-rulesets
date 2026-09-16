rule Trojan_Win64_IcedID_EA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 54 24 10 48 89 4c 24 08 eb d7 80 44 24 4b 28 c6 44 24 4c 4e eb 00 80 44 24 4c 26 c6 44 24 4d 62 eb 18 44 89 4c 24 20 4c 89 44 24 18 eb d0 80 44 24 4a 07 c6 44 24 4b 4a eb d0 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}