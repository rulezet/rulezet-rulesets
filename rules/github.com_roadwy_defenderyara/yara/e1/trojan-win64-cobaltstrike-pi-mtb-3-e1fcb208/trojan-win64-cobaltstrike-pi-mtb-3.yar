rule Trojan_Win64_CobaltStrike_PI_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 0f af c8 41 8b ?? 03 c1 48 63 c8 48 8b 44 24 ?? 0f b6 0c 08 48 8b 44 24 ?? 42 0f b6 34 ?? 33 f1 8b 4c 24 ?? 8b 44 24 ?? 03 c1 } 		$a_03_1 = {41 2b c3 2b c3 2b c7 8b c8 48 8b 44 24 ?? 40 88 34 08 e9 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}