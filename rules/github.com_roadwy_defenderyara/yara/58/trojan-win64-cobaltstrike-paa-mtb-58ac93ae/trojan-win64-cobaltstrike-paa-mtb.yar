rule Trojan_Win64_CobaltStrike_PAA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 48 8b 1d [0-06] 31 ff 65 48 8b 04 25 30 00 00 00 48 8b 2d cd d0 00 00 48 8b 70 08 eb 17 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}