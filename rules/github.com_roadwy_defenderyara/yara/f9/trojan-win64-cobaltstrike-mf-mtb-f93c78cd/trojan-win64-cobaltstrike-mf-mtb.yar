rule Trojan_Win64_CobaltStrike_MF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 fd 00 00 00 88 05 ab 54 00 00 0f b6 05 a4 54 00 00 83 e0 6e 88 05 9b 54 00 00 0f b6 05 94 54 00 00 83 c8 43 88 05 8b 54 00 00 0f b6 05 84 54 00 00 2d 82 a3 09 53 89 05 75 54 00 00 0f b6 05 72 54 00 00 0d ca da ac 51 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}