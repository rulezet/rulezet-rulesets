rule Trojan_Win64_CobaltStrike_ZE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 2b c1 48 0f af c6 48 03 c8 48 0f af ff 48 8d 04 7f 48 2b c8 49 03 cd 42 0f b6 94 32 ?? ?? ?? ?? 42 32 94 31 ?? ?? ?? ?? 48 8d 04 76 49 8b cd 48 2b c8 48 8b 84 24 ?? ?? ?? ?? 88 14 01 41 ff c4 49 ff c5 49 63 c4 48 3b 84 24 ?? ?? ?? ?? 73 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}