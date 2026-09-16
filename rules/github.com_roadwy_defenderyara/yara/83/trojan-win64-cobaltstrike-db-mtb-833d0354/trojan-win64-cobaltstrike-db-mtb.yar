rule Trojan_Win64_CobaltStrike_DB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 11 0f b6 c2 41 32 c0 88 01 44 0f b6 c2 48 ff c1 49 3b c9 72 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}