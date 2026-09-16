rule Trojan_Win64_CobaltStrike_ACB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 48 8d 5b 01 f7 fd fe c2 32 54 1e ff 41 32 d6 88 53 ff 48 83 ef 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}