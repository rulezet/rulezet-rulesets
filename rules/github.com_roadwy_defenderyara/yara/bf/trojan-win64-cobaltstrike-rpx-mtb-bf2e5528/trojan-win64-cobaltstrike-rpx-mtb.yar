rule Trojan_Win64_Cobaltstrike_RPX_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7 } 		$a_01_1 = {49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}