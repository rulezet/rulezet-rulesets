rule Trojan_BAT_AgentTesla_AGK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 0f 1f 49 5a 20 ff 00 00 00 5f d2 13 10 11 04 11 0f 6f 25 00 00 0a 1f 13 8f 3e 00 00 01 25 47 11 10 61 d2 52 11 0f 17 58 13 0f 11 0f 11 07 32 cf } 		$a_81_1 = {57 69 6e 46 6f 72 6d 53 65 72 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_00_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}