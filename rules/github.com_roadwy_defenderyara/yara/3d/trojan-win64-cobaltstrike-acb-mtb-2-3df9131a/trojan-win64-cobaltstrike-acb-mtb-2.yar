rule Trojan_Win64_CobaltStrike_ACB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 c9 8d 04 1a 41 32 44 10 10 49 c1 f9 08 44 31 c8 49 89 c9 48 c1 f9 18 49 c1 f9 10 44 31 c8 31 c8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}