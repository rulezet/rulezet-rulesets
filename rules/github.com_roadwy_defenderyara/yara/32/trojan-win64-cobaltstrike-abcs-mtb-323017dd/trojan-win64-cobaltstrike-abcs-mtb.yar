rule Trojan_Win64_CobaltStrike_ABCS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ABCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 48 99 49 f7 f9 41 0f b6 04 13 41 30 04 0a 48 ff c1 48 89 0c 24 4c 39 04 24 ?? ?? 48 8b 0c 24 48 89 c8 4c 09 c8 48 c1 e8 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}