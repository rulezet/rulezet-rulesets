rule Trojan_Win64_CobaltStrike_MX_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f 00 48 83 c0 10 48 83 c2 10 66 0f ef c1 0f 11 42 f0 48 39 c8 75 e7 c7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}