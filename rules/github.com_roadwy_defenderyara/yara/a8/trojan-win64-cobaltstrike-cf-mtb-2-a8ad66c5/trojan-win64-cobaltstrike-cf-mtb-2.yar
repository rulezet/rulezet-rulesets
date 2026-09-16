rule Trojan_Win64_CobaltStrike_CF_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0b 48 8d 54 24 ?? 4c 8b c7 ff 15 ?? ?? ?? ?? 3d 0d 00 00 c0 74 ?? 48 83 c7 ?? 48 83 c3 ?? 48 3b dd 7c ?? 33 d2 48 8b ce ff 15 ?? ?? ?? ?? eb } 		$a_01_1 = {2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}