rule Trojan_Win64_CobaltStrike_BY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 34 38 81 83 c0 02 3b c3 72 f5 ff d7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}