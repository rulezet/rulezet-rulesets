rule Trojan_Win64_CobaltStrike_GFT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 00 48 03 44 24 28 48 89 84 24 88 00 00 00 48 8b 84 24 88 00 00 00 0f b6 00 0f b6 4c 24 20 33 c1 89 44 24 30 0f b6 44 24 30 88 44 24 21 48 8d 44 24 21 48 89 84 24 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}