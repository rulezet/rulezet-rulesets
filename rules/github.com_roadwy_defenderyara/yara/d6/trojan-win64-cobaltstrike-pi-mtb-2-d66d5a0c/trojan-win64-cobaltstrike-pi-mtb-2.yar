rule Trojan_Win64_CobaltStrike_PI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 17 30 04 0e 8d 41 ?? 99 f7 fb 0f b6 04 17 30 44 0e ?? 48 8d 41 ?? 44 39 c8 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}