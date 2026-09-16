rule Trojan_Win64_IcedID_MF_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 43 58 48 8b 83 a8 00 00 00 44 89 93 dc 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 43 5c 48 63 4b 5c 48 8b 83 a8 00 00 00 44 88 04 01 ff 43 5c 8b 8b e8 00 00 00 8b d1 44 8b 83 dc 00 00 00 41 2b d0 8b 43 38 41 03 d2 03 c1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}