rule Trojan_Win64_Cobaltstrike_RPY_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 00 02 04 00 48 8b cb ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}