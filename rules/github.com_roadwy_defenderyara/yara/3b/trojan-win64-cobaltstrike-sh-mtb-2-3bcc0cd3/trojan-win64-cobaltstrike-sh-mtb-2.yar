rule Trojan_Win64_CobaltStrike_SH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.SH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 48 8d 0d d0 11 00 00 0f be 04 01 89 44 24 24 8b 44 24 20 99 83 e0 01 33 c2 2b c2 48 98 48 8b 4c 24 38 0f be 04 01 8b 4c 24 24 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}