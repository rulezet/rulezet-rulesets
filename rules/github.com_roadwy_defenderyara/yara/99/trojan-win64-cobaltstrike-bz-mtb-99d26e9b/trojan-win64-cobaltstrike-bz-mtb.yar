rule Trojan_Win64_CobaltStrike_BZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 40 20 40 00 00 00 48 c7 40 28 00 00 00 08 48 c7 40 30 00 00 00 00 48 89 c3 b9 07 00 00 00 48 89 cf } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}