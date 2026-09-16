rule Trojan_BAT_AgentTesla_ABF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 7e 02 00 00 04 18 06 0c 9a 20 81 0b 00 00 95 5a 7e 02 00 00 04 18 9a 20 a7 0d 00 00 95 58 61 81 05 00 00 01 } 		$a_01_1 = {95 e0 95 2d 06 16 09 13 08 2b 01 17 7e 1c 01 00 04 17 9a 20 b1 01 00 00 95 5a 7e 1c 01 00 04 17 9a 20 c2 01 00 00 95 58 61 80 18 00 00 04 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}