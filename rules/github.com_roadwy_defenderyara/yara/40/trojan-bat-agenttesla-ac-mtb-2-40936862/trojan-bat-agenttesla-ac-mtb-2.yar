rule Trojan_BAT_AgentTesla_AC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 9a 20 0c 07 00 00 95 5f 7e 06 00 00 04 19 9a 20 86 08 00 00 95 61 59 81 07 00 00 01 7e 06 00 00 04 17 9a 1f 10 95 } 		$a_01_1 = {2d 03 16 2b 01 17 17 59 7e 2c 00 00 04 20 53 02 00 00 95 5f 7e 2c 00 00 04 20 8b 01 00 00 95 61 58 81 07 00 00 01 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=4
 
}