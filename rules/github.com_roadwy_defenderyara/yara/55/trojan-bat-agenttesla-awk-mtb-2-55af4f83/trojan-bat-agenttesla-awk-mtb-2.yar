rule Trojan_BAT_AgentTesla_AWK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 17 d6 13 07 11 07 07 6f 66 00 00 0a fe 04 13 0d 11 0d 3a 51 ff ff ff } 		$a_01_1 = {54 65 78 74 42 6f 78 4d 61 73 6b 49 6e 70 75 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}