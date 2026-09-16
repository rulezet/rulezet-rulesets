rule Trojan_Win64_CobaltStrike_LIT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 48 2b d7 88 04 17 ff c1 8b c1 48 ff c7 25 03 00 00 80 7d ?? ff c8 83 c8 fc ff c0 48 98 8a 04 18 32 07 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}