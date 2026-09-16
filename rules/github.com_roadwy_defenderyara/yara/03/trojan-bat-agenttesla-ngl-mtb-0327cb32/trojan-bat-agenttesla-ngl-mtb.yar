rule Trojan_BAT_AgentTesla_NGL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f ab 00 00 0a b4 13 09 11 09 02 18 91 fe 01 13 1d 11 1d 39 fd 00 00 00 } 		$a_01_1 = {56 54 56 58 56 59 56 5a 42 6f 64 79 44 69 61 67 6e 6f 73 74 69 63 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}