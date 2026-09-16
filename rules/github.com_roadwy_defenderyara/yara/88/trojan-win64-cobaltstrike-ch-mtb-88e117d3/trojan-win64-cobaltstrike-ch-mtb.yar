rule Trojan_Win64_CobaltStrike_CH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ea 29 ca 48 63 ca 0f b6 0c 0e 32 0c 03 41 88 0c 06 b8 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}