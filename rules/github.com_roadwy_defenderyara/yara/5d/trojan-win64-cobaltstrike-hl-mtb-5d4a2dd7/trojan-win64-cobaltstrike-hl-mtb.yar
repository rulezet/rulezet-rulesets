rule Trojan_Win64_Cobaltstrike_HL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 0c 06 69 c9 07 c1 7d 00 81 f1 97 57 23 b8 41 30 4c 06 01 48 83 c0 02 48 39 c2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}