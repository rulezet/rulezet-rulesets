rule Trojan_Win64_Cobaltstrike_EN_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 c1 f9 1f 29 ca 6b ca 36 29 c8 89 c2 89 d0 83 c0 38 44 89 c1 31 c1 48 8b 95 10 03 00 00 8b 85 04 03 00 00 48 98 88 0c 02 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}