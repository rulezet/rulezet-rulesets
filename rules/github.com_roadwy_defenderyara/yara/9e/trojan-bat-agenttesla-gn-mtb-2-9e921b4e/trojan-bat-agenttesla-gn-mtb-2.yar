rule Trojan_BAT_AgentTesla_GN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 20 15 00 cf 30 20 00 00 80 00 58 20 00 00 80 00 59 fe 0e 0b 00 fe 0d 0b 00 00 48 68 d3 13 0a 38 } 		$a_01_1 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}