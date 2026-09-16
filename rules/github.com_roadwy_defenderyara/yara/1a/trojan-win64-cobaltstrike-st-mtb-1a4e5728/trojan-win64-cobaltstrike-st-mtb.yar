rule Trojan_Win64_CobaltStrike_ST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 b8 48 8b 55 e0 4c 8b 45 b0 8a 4d af 42 32 0c 02 88 08 48 8b 45 08 48 83 c0 01 48 89 45 a0 0f 92 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}