rule Trojan_Win64_CobaltStrike_BQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 89 f1 44 32 0c 0f 44 88 0c 08 48 83 c1 ?? 39 cb 7f } 		$a_03_1 = {41 8b 08 81 e2 ?? ?? ?? ?? 48 8d 04 13 4c 01 14 01 eb ?? 45 33 f6 41 8b d6 44 ?? ?? ?? 0f 86 ?? ?? ?? ?? 8b ca 03 d6 8a 04 29 88 04 19 3b 57 ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}