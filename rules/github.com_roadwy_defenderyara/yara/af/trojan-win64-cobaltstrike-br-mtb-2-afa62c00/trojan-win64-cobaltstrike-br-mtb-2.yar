rule Trojan_Win64_CobaltStrike_BR_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 68 39 c3 7e 16 48 89 c2 83 e2 07 41 8a 54 15 00 32 14 07 88 14 01 48 ff c0 eb } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}