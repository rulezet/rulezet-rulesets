rule Trojan_BAT_AgentTesla_CAI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_00_0 = {d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a } 		$a_00_1 = {db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 } 		$a_00_2 = {d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 } 		$a_00_3 = {d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 } 		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } 		$a_81_5 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } 		$a_81_6 = {47 65 74 54 79 70 65 } 		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=42
 
}