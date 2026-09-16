rule Trojan_BAT_AgentTesla_AL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 9a 20 21 03 00 00 95 e0 95 7e 60 00 00 04 18 9a 20 8e 04 00 00 95 61 08 0a 7e 60 00 00 04 18 9a 20 df 0d 00 00 95 2e 03 17 2b 01 16 58 } 		$a_01_1 = {18 9a 20 68 0c 00 00 95 2e 03 16 2b 01 17 17 59 7e 60 00 00 04 18 9a 20 40 0a 00 00 95 5f 7e 60 00 00 04 18 9a 20 91 0f 00 00 95 61 58 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}