rule Trojan_Win64_CobaltStrike_YAG_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 d0 c1 c2 08 e9 ce a4 01 00 e9 } 		$a_03_1 = {48 c7 04 24 65 00 00 00 90 13 48 ?? ?? ?? ?? 78 00 00 00 48 ?? ?? ?? ?? 70 00 00 00 48 ?? ?? ?? ?? 6c 00 00 00 90 13 48 ?? ?? ?? ?? 6f 00 00 00 48 ?? ?? ?? ?? 72 00 00 00 48 c7 44 24 06 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}