rule Trojan_BAT_AgentTesla_ENS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ENS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 30 fe 68 37 47 41 30 4a 78 76 66 8e ae 76 44 f7 35 6a 6e 68 34 47 41 70 4e 78 76 66 71 51 76 44 4f 35 6a 6e 68 34 47 41 30 4e 78 76 66 71 51 } 		$a_01_1 = {4e 70 7e 6e b0 94 73 80 5c 36 79 7e a9 f9 4a 8d b2 c8 7e f2 d7 f8 68 ce b7 80 0a 96 1f 25 09 3b 80 f1 4f b8 47 67 40 61 87 81 7a c1 e8 e4 62 bc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}