rule Trojan_Win64_IcedID_F_MTB{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 c0 02 48 89 44 24 40 e9 30 04 00 00 8a 40 01 88 44 24 21 66 3b d2 74 1a 48 03 c8 48 8b c1 66 3b ed 74 e9 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}