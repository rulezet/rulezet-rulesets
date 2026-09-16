rule Trojan_Win64_CobaltStrike_BO_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 1f e8 ?? ?? ?? ?? 33 d2 48 98 48 2b f5 48 f7 f6 49 8b 07 fe c2 41 32 14 06 42 88 14 33 48 8b 0f 46 30 24 31 49 ff c6 49 8b 77 ?? 49 8b 2f 48 8b ce 48 2b cd 4c 3b f1 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}