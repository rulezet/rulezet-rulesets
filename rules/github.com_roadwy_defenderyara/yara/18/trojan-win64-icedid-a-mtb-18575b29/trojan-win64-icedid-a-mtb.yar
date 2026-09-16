rule Trojan_Win64_IcedID_A_MTB{
	meta:
		description = "Trojan:Win64/IcedID.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 49 78 0f b6 54 24 70 88 14 01 48 8b 84 24 60 01 00 00 8b 40 48 ff c0 48 8b 8c 24 60 01 00 00 89 41 48 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}