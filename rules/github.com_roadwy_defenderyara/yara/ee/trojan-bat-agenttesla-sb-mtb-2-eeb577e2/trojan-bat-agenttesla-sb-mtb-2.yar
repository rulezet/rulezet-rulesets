rule Trojan_BAT_AgentTesla_SB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 18 5a 18 6f 6c 00 00 0a 1f 10 28 6d 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } 		$a_01_1 = {41 6d 69 67 6f 53 65 63 72 65 74 6f 57 69 6e 46 6f 72 6d 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}