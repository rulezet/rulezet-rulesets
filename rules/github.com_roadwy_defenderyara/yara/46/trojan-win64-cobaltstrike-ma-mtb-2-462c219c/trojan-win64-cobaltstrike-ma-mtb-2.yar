rule Trojan_Win64_CobaltStrike_MA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af 48 68 8b c1 89 44 24 34 8b 44 24 34 c1 e8 10 48 8b 8c 24 [0-04] 48 63 49 6c 48 8b 94 24 [0-04] 48 8b 92 a0 00 00 00 88 04 0a 48 8b 84 24 [0-04] 8b 40 6c ff c0 48 8b 8c 24 [0-04] 89 41 6c 8b 44 24 34 c1 e8 08 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}