rule Trojan_Win64_CobaltStrike_DE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 05 e0 4c 8d 48 01 41 32 48 ff 48 63 c2 ff c2 48 03 45 c0 88 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}