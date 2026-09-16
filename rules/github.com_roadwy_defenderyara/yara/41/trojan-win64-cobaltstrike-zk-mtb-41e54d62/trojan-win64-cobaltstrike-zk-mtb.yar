rule Trojan_Win64_CobaltStrike_ZK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 4c 8b 04 25 60 00 00 00 4d 8b 40 18 4d 8b 40 20 4d 89 c3 49 8b 50 50 51 4c 89 d0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}