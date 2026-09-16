rule Trojan_Win64_CobaltStrike_GZZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 c7 44 24 ?? 00 00 00 00 ba ?? ?? ?? ?? 41 b8 00 30 00 00 44 8d 49 ?? ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}