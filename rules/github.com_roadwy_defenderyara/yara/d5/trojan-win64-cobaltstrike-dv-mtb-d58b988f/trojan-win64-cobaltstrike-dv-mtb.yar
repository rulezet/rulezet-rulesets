rule Trojan_Win64_Cobaltstrike_DV_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 d1 48 8b ca 48 33 c8 48 8b c1 48 0f be 4c 24 30 48 33 c8 48 8b c1 48 8b 8c 24 f0 00 00 00 88 84 0c ac 00 00 00 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}