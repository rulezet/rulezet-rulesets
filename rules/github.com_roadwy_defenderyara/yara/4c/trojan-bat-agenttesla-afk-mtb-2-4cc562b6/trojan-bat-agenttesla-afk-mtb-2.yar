rule Trojan_BAT_AgentTesla_AFK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 48 48 48 38 38 37 2e 70 64 62 } 		$a_01_1 = {48 48 48 38 38 37 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_01_2 = {24 34 32 38 39 62 31 39 35 2d 61 63 36 36 2d 34 31 63 38 2d 62 36 38 30 2d 36 38 37 64 30 32 34 62 66 33 31 37 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}