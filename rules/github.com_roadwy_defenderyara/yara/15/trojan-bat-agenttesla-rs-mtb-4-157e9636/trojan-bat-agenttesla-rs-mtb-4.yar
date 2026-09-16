rule Trojan_BAT_AgentTesla_RS_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f a4 00 00 0a 72 73 0c 00 70 72 77 0c 00 70 } 		$a_01_1 = {07 06 11 07 9a 1f 10 28 a7 00 00 0a 6f a8 00 00 0a 00 11 07 17 58 13 07 11 07 20 00 ea 00 00 fe 04 13 08 11 08 2d d9 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}