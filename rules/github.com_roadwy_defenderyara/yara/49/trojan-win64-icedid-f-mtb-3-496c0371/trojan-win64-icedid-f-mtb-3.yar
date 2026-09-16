rule Trojan_Win64_IcedID_F_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 48 8b 4c 24 40 e9 57 01 00 00 8a 00 88 44 24 20 eb e9 48 8b 44 24 38 48 8b 4c 24 40 66 3b db 74 00 48 03 c8 48 8b c1 3a db 74 df } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}