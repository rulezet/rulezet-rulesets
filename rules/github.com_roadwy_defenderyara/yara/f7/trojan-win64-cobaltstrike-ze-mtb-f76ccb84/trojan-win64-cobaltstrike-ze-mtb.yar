rule Trojan_Win64_CobaltStrike_ZE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 c1 08 da 44 20 c3 08 cb 89 d9 30 c1 20 d9 44 08 c0 89 d3 30 c3 08 d0 34 01 08 d8 89 cb 80 f3 01 89 c2 80 f2 01 20 d8 08 d3 20 ca 08 c2 89 d9 30 d1 be ?? ?? ?? ?? b8 ?? ?? ?? ?? f6 c1 01 75 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}