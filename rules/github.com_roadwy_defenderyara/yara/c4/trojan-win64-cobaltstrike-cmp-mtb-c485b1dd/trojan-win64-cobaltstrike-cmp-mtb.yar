rule Trojan_Win64_CobaltStrike_CMP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 85 a0 09 c1 89 ca 8b 85 a4 01 00 00 48 98 48 8d 48 02 48 8b 85 98 01 00 00 48 01 c8 88 10 83 85 a4 01 00 00 03 83 85 a8 01 00 00 04 8b 85 a0 01 00 00 83 e8 02 39 85 a8 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}