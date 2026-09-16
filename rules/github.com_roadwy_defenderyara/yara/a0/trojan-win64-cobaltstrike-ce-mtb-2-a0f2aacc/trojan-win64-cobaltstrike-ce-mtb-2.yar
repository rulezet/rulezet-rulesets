rule Trojan_Win64_CobaltStrike_CE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ca 48 ff c2 83 e1 ?? 42 8a 0c 31 32 0c 2b 88 0b 48 ff c3 48 ff c8 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}