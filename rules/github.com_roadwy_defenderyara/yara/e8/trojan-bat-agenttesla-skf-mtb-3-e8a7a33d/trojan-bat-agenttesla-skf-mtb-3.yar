rule Trojan_BAT_AgentTesla_SKF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {13 0c 11 0c 1f 7b 61 20 ff 00 00 00 5f 13 0d 11 0d 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0d 11 0d 16 fe 01 13 0e 11 0e 2c 03 17 13 0d 09 11 0b 07 11 0b 91 11 04 11 0c 95 61 d2 9c 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0f 11 0f 3a 66 ff ff ff } 		$a_81_1 = {41 50 37 48 39 48 35 4f 49 34 34 37 38 46 38 43 48 30 35 46 47 41 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}