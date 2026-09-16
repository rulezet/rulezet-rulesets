rule Trojan_Win64_CobaltStrike_ASJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 df 48 89 ce 48 8b 5c 24 ?? 48 89 c1 48 8b 44 24 ?? e8 ?? ?? ?? ?? 48 89 44 24 48 48 89 5c 24 58 48 8b 4c 24 38 48 8d ?? ?? ?? ?? 00 48 89 cb e8 ?? ?? ?? ?? 48 89 44 24 } 		$a_01_1 = {6d 61 69 6e 2e 41 65 73 44 65 63 72 79 70 74 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}