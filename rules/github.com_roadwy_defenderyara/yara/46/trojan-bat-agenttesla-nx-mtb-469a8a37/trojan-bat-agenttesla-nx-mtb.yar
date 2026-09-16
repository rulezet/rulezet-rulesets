rule Trojan_BAT_AgentTesla_NX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 } 		$a_01_1 = {24 33 33 66 65 35 63 33 32 2d 64 62 36 61 2d 34 64 37 61 2d 61 64 64 63 2d 65 31 64 30 64 38 35 38 38 66 61 39 } 		$a_01_2 = {47 65 74 54 79 70 65 } 		$a_01_3 = {54 77 65 65 6e 45 6e 67 69 6e 65 41 50 49 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}