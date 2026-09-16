rule Trojan_Win64_IcedID_MP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af 56 68 05 24 c2 13 00 01 46 58 48 63 4e 6c 48 8b 86 a8 00 00 00 88 14 01 44 8b 86 e0 00 00 00 8b 96 bc 00 00 00 44 8b 9e 34 01 00 00 8b 9e 18 01 00 00 ff 46 6c 41 8d 48 ed 03 4e 78 09 4e 78 8b 4e 44 8b c1 33 86 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}