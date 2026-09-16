rule Trojan_BAT_AgentTesla_AA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}