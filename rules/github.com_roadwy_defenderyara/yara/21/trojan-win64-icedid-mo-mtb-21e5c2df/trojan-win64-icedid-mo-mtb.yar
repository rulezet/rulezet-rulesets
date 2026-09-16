rule Trojan_Win64_IcedID_MO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8b d5 49 8b ce eb aa 30 41 ff 8b 47 18 eb 00 3b d8 72 0f } 		$a_01_1 = {76 63 61 62 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}