rule Trojan_Win64_CobaltStrike_CCHW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 56 01 45 0f b6 59 02 45 31 c3 45 0f b6 41 01 45 31 d8 4c 39 d2 73 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}