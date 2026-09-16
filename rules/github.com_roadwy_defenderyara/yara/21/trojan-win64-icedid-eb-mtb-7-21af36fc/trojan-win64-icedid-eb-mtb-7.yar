rule Trojan_Win64_IcedID_EB_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 50 fc ff ff 66 89 84 24 8e 00 00 00 b8 15 00 00 00 eb 00 83 c0 5b 66 89 84 24 90 00 00 00 eb 17 83 c0 2c 66 89 84 24 8c 00 00 00 eb 00 b8 3c 00 00 00 83 c0 33 eb cd } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}