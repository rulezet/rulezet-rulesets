rule Trojan_Win64_CobaltStrike_MD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 0c 0f 4c 8d 15 8c d6 03 00 47 0f b6 1c 02 47 0f b6 14 11 41 80 fb 0f 77 ?? 41 80 fa 0f 77 ?? 41 c1 e3 04 45 09 d3 48 39 d3 77 } 		$a_03_1 = {48 89 84 24 80 00 00 00 48 c7 40 08 12 00 00 00 48 8d 0d a0 08 02 00 48 89 08 ?? 48 8d 05 11 59 01 00 e8 ?? ?? ?? ?? 83 3d 25 63 12 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}