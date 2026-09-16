rule Trojan_BAT_AgentTesla_NYN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 0b 07 16 fe 02 13 06 11 06 2c 2e 06 } 		$a_01_1 = {17 02 1e 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 af 00 00 00 40 00 00 00 bd 00 00 00 55 01 00 00 20 01 00 00 12 00 00 00 6a 01 00 00 58 } 		$a_01_2 = {24 34 33 38 31 39 30 31 34 2d 62 61 33 62 2d 34 36 33 39 2d 38 32 63 66 2d 64 33 62 37 62 30 39 34 32 30 66 38 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}