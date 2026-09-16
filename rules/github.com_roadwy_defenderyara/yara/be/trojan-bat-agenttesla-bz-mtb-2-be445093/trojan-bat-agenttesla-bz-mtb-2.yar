rule Trojan_BAT_AgentTesla_BZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 62 76 73 4f 43 63 4f 42 5a 68 7a 71 61 48 } 		$a_01_1 = {3d 00 3d 00 3d 00 3d 00 3d 00 4d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 61 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 69 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 6e 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}