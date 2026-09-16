rule Trojan_BAT_AgentTesla_MBKA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 7a 00 76 00 77 00 2e 00 4c 00 64 00 69 00 75 00 68 00 74 00 6a 00 74 00 68 00 77 00 00 11 58 00 62 00 72 00 68 00 63 00 6c 00 72 00 6f } 		$a_01_1 = {71 00 75 00 2e 00 61 00 78 00 2f 00 6d 00 44 00 48 00 6c 00 2e 00 70 } 		$a_01_2 = {36 64 31 64 36 37 31 35 30 62 31 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}