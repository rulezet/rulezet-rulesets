rule Trojan_Win64_IcedID_EB_MTB_12{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb aa 80 44 24 44 67 c6 44 24 45 27 eb aa 80 44 24 46 13 c6 44 24 47 37 e9 e5 fe ff ff 48 8d 94 24 88 00 00 00 48 8b 4c 24 38 e9 49 fd ff ff 44 8b 4c 24 60 4c 8d 84 24 80 00 00 00 eb df b8 01 00 00 00 83 c0 00 eb 38 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}