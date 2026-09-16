rule Trojan_Win64_CobaltStrike_BL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 85 f6 74 26 41 8a 44 2c 10 48 8b bc 24 88 00 00 00 32 84 33 e8 03 00 00 48 ff c6 83 e6 0f 88 44 2f 10 48 ff c5 e9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}