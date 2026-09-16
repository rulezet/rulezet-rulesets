rule Trojan_BAT_AgentTesla_ABP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 05 11 0a 8f 13 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } 		$a_01_1 = {36 00 37 00 2e 00 30 00 2e 00 33 00 33 00 39 00 36 00 2e 00 38 00 37 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}