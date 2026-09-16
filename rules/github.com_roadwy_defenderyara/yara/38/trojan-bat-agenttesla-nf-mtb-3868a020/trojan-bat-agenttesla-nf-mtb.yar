rule Trojan_BAT_AgentTesla_NF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff b7 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c7 00 00 00 78 07 00 00 07 08 00 00 ce 68 00 00 d7 } 		$a_01_1 = {8a 00 00 cc 03 00 00 c8 01 00 00 8c 03 00 00 9d 0d 00 00 16 73 00 00 02 00 00 00 05 00 00 00 2c 00 00 00 e5 00 } 		$a_01_2 = {38 41 38 44 30 42 42 34 38 35 45 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}