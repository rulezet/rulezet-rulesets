rule Trojan_Win64_CobaltStrike_SCD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 4c 8b 49 10 49 8b 49 30 48 85 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}