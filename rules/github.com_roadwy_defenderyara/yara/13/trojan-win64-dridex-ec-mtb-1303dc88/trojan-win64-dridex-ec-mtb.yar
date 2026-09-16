rule Trojan_Win64_Dridex_EC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 32 f6 33 ff 42 8b 94 28 88 00 00 00 41 89 d2 46 8b 8c 28 8c 00 00 00 44 03 ca 43 8b 44 2a 20 47 8b 44 2a 24 49 03 c5 4d 03 c5 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}