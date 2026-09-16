rule Trojan_Win64_IcedID_MQ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 46 54 2d ab 9f 01 00 09 46 04 48 8b 86 c0 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 46 60 8b 86 e8 00 00 00 48 63 4e 60 2d 93 ab 18 00 01 86 90 00 00 00 48 8b 86 c0 00 00 00 44 88 04 01 ff 46 60 8b 86 ec 00 00 00 ff c8 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}