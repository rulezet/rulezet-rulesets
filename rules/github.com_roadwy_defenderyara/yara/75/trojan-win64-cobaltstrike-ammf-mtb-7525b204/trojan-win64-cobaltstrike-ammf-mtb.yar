rule Trojan_Win64_CobaltStrike_AMMF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 f1 83 e1 0f 0f b6 0c 01 42 32 0c 33 42 88 0c 37 49 ff c6 48 8b 5d ?? 48 8b 4d ?? 48 29 d9 49 39 ce } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}