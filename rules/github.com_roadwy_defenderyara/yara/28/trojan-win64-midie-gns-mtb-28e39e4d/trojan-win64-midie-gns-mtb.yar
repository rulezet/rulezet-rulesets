rule Trojan_Win64_Midie_GNS_MTB{
	meta:
		description = "Trojan:Win64/Midie.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 c1 86 36 32 1a 95 2a a4 4d } 		$a_03_1 = {8c 11 42 36 ee 97 a4 bc ?? ?? ?? ?? cc 31 d1 32 2e 59 00 76 10 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}