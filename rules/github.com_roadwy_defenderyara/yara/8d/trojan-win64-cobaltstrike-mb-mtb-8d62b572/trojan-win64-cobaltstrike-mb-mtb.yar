rule Trojan_Win64_CobaltStrike_MB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 c0 41 b9 9e 03 00 00 49 8b c0 49 ff c0 83 e0 0f 8a 04 10 30 01 48 ff c1 49 83 e9 01 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}