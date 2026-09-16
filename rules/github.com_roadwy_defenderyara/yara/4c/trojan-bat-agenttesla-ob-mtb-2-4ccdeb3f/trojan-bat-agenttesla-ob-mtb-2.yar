rule Trojan_BAT_AgentTesla_OB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 3d 72 eb 02 3d 72 3d 72 e3 02 3d 72 3d 72 cd 02 cd 02 d6 02 3d 72 ea 02 05 03 3d 72 3d 72 3d 72 3d 72 df 02 ef } 		$a_01_1 = {d6 02 03 03 e6 02 d1 02 ef 02 0d 03 e2 02 ef 02 3d 72 e0 02 0e 03 15 03 0a 03 e4 02 16 03 e7 02 e4 02 e7 02 e7 02 09 03 3d 72 3d 72 05 03 d2 02 05 03 3d 72 df 02 e1 } 		$a_01_2 = {df 02 18 03 df 02 e1 02 d2 02 df 02 eb 02 3d 72 13 03 df 02 e2 02 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 3d 72 } 		$a_80_3 = {42 23 75 6e 23 69 66 75 23 5f 54 65 78 23 74 42 6f 23 78 } 		$a_80_4 = {23 47 65 74 23 4d 65 74 23 68 6f 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}