rule Trojan_Win64_CobaltStrike_AB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 48 89 d8 83 e0 07 8a 44 05 00 30 04 ?? 48 ff c3 48 83 fb 40 75 e8 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}