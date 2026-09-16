rule Trojan_BAT_AgentTesla_NGC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 df 02 df 02 df 02 df 02 cd 02 cd 02 d6 02 df 02 df 02 ea 02 05 03 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 ef } 		$a_01_1 = {03 05 03 d2 02 df 02 12 03 df 02 0c 03 ec 02 e7 02 00 03 05 03 e0 02 f2 02 eb 02 ce 02 06 03 f4 02 e5 02 06 03 0e 03 01 03 17 03 e0 02 15 03 01 } 		$a_01_2 = {02 07 03 e3 02 ea 02 df 02 ef 02 05 03 df 02 df 02 e2 02 0d 03 df 02 df 02 df 02 df 02 e5 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 e2 } 		$a_01_3 = {02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 e0 02 ef 02 df 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 e2 02 05 03 df 02 df 02 df 02 df 02 df 02 } 		$a_01_4 = {12 03 df 02 e5 02 e7 02 df 02 00 03 df 02 e0 02 d3 02 df 02 e1 02 df 02 df 02 f4 02 05 03 e0 02 0a 03 df 02 e6 02 e7 02 df 02 01 03 15 03 e0 02 0e 03 df 02 e5 } 		$a_01_5 = {5f 41 00 5f 42 00 5f 43 00 5f 44 00 5f 45 00 5f 46 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}