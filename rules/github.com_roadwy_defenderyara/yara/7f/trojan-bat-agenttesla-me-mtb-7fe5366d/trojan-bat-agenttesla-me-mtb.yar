rule Trojan_BAT_AgentTesla_ME_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 91 02 7b [0-04] 16 9a 6f [0-04] d2 02 7b [0-04] 17 9a 6f [0-04] d2 61 d2 61 d2 9c } 		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_80_2 = {41 63 74 69 76 61 74 6f 72 } 		$a_80_3 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } 		$a_80_4 = {41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}