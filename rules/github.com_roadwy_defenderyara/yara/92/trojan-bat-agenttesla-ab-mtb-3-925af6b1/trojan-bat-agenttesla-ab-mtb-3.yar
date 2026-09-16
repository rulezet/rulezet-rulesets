rule Trojan_BAT_AgentTesla_AB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 29 11 16 1f 41 61 13 16 11 16 1f 4b 59 45 06 00 00 00 0b 00 00 00 1c 00 00 00 34 00 00 00 43 00 00 00 59 00 00 00 66 00 00 00 1f 42 28 ?? 00 00 06 13 16 2b cc 11 0c 11 0d fe 01 16 fe 01 13 0e 1f 0e 13 16 2b bb 11 08 11 0b 5f 11 0a 1f 1f 5f 63 13 0d 1f 3d 28 ?? 00 00 06 13 16 2b a3 } 		$a_01_1 = {24 36 64 61 65 63 31 31 39 2d 31 63 32 31 2d 34 37 61 62 2d 39 37 63 66 2d 61 35 31 38 35 35 62 64 34 34 34 31 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}