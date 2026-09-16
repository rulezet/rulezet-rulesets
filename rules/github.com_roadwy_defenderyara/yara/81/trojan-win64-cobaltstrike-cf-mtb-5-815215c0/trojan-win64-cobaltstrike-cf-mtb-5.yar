rule Trojan_Win64_CobaltStrike_CF_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.CF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 14 25 30 00 00 00 48 89 90 a6 08 00 00 48 8b 80 a6 08 00 00 48 8b 40 60 48 8b 40 18 48 8b 58 10 48 8d 78 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}