rule Trojan_Win64_CobaltStrike_BR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 58 41 8b c3 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 8d 04 92 3b c8 8b 44 24 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}