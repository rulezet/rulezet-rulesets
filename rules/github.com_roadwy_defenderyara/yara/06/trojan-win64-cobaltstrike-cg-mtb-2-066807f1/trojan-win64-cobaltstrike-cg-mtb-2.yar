rule Trojan_Win64_CobaltStrike_CG_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 8d 80 00 00 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 4d 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d 80 00 00 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 4d 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d 80 00 00 00 e8 } 		$a_03_1 = {83 e8 03 48 98 c6 84 05 ?? ?? 00 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d ?? ?? 00 00 e8 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}