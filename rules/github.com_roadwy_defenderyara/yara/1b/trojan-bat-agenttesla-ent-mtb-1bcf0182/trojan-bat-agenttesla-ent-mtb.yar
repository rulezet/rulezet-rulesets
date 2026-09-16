rule Trojan_BAT_AgentTesla_ENT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c4 d2 c0 d3 af ad 91 04 22 ee 59 a2 43 00 49 89 d6 ed 2f 45 e1 bf fc f0 c0 33 af af cf a5 95 cf 52 42 43 20 49 49 49 2f 2a 45 21 3f 3c d0 c0 53 } 		$a_01_1 = {5e 42 21 ed 45 b8 c0 61 09 47 39 3f 3c d0 c0 d3 e9 16 72 64 ed 33 bc be 4a 20 49 49 55 2f 90 b4 68 02 9e 25 a3 26 a1 ad cf bb a9 cf 10 41 41 93 } 		$a_01_2 = {a9 cf 5e 42 43 20 49 49 55 2f 2e 45 21 3f 3c d0 c0 d3 af ad cf bb a9 cf 5e 42 43 20 49 49 55 2f 2e 45 21 3f 3c d0 c0 d3 af ad cf bb a9 cf 5e 42 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}