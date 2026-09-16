rule Trojan_Win64_Cobaltstrike_HQ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 30 fa 80 70 0a fa 48 83 c0 14 4c 39 c0 75 f0 } 		$a_01_1 = {80 30 1a 80 70 07 1a 48 83 c0 0e 49 39 c0 75 f0 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}