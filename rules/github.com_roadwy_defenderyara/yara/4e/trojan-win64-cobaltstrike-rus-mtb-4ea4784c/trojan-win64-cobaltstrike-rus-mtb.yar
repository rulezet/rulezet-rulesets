rule Trojan_Win64_CobaltStrike_RUS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 6c 24 40 48 89 4d e8 48 89 55 f0 66 c7 45 f8 01 00 48 8d 4d e8 e8 5f 2e 04 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}