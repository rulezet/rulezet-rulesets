rule Trojan_Win64_CobaltStrike_BV_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f 4c f0 eb ?? 48 63 5c 24 ?? 48 63 7c 24 ?? 48 69 f7 ?? ?? ?? ?? 48 89 f1 48 c1 e9 ?? 48 c1 ee ?? 01 ce 6b ce ?? 29 cf 40 80 c7 ?? 40 30 7c 1c ?? 8b 5c 24 ?? ff c3 eb ?? bb ?? ?? ?? ?? e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}