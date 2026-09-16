rule Trojan_BAT_AgentTesla_ABO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 bf 08 00 00 95 6e 31 03 16 2b 01 17 7e 3c 00 00 04 16 9a 20 97 0e 00 00 95 5a 7e 3c 00 00 04 16 9a 20 24 0e 00 00 95 58 61 81 07 00 00 01 } 		$a_01_1 = {95 61 7e 21 00 00 04 20 35 09 00 00 95 2e 03 16 2b 01 17 17 59 7e 21 00 00 04 20 1a 13 00 00 95 5f 7e 21 00 00 04 20 a1 0d 00 00 95 61 58 81 05 00 00 01 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}