rule Trojan_Win64_CobaltStrike_RD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 50 48 8d 44 24 70 48 89 4c 24 48 41 b9 ff 01 0f 00 48 89 4c 24 40 48 8b cb 48 89 44 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 03 00 00 00 c7 44 24 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}