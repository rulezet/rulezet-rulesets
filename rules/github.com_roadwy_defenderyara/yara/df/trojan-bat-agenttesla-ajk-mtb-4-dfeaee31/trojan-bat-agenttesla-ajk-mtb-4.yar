rule Trojan_BAT_AgentTesla_AJK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 61 31 62 32 63 33 64 34 2d 65 35 66 36 2d 34 37 61 38 2d 62 39 63 30 2d 64 31 65 32 66 33 61 34 62 35 63 36 } 		$a_81_1 = {41 68 6f 72 63 61 64 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {4a 75 65 67 6f 20 64 65 6c 20 41 68 6f 72 63 61 64 6f 20 2d 20 50 72 6f 79 65 63 74 6f 20 55 6e 69 76 65 72 73 69 74 61 72 69 6f } 	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}