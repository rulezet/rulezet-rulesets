rule Trojan_Win64_IcedID_EC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 43 58 48 8b 83 a8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 43 6c } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}