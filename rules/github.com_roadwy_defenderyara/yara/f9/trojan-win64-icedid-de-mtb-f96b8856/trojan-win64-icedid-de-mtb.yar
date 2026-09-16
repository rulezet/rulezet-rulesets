rule Trojan_Win64_IcedID_DE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 44 24 58 2c c7 44 24 5c 54 00 00 00 66 3b db 74 44 83 44 24 68 13 c7 44 24 6c eb 01 00 00 3a d2 74 48 83 44 24 54 16 c7 44 24 58 17 00 00 00 3a d2 74 cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}