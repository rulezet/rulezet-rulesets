rule Trojan_Win64_CobaltStrike_LP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.LP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 48 33 c9 65 48 8b 41 60 48 8b 40 18 48 8b 70 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}