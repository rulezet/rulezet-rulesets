rule Trojan_BAT_AgentTesla_PC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 04 95 11 07 11 05 95 58 d2 13 16 11 07 11 16 20 ff 00 00 00 5f 95 d2 13 17 11 15 11 17 61 13 18 11 08 11 12 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}