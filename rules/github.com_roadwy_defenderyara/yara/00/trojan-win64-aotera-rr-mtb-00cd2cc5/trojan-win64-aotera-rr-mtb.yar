rule Trojan_Win64_Aotera_RR_MTB{
	meta:
		description = "Trojan:Win64/Aotera.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b d1 8b c1 33 44 97 10 44 03 c0 8b d1 41 2b d2 41 c1 c0 11 44 33 c2 41 8b d2 8b c1 41 33 c0 89 44 96 10 41 ff c2 41 83 fa 18 0f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}