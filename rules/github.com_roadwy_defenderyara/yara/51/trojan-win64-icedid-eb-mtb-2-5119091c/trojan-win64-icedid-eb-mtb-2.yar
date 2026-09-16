rule Trojan_Win64_IcedID_EB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 40 b9 ab 01 00 00 2b c8 8b 45 40 2b c8 83 c1 2b 89 4d 40 8a 45 48 88 02 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}