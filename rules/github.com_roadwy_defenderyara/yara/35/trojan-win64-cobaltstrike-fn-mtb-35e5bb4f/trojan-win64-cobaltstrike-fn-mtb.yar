rule Trojan_Win64_CobaltStrike_FN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 31 c3 89 da 8b 85 d8 b0 04 00 48 98 88 54 05 70 83 85 dc b0 04 00 01 83 85 d8 b0 04 00 01 8b 85 d8 b0 04 00 48 98 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}