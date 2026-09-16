rule Trojan_BAT_SnakeKeylogger_MK_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } 		$a_01_1 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 } 		$a_01_2 = {43 72 65 64 65 6e 74 69 61 6c 4d 6f 64 65 6c } 		$a_01_3 = {67 65 74 5f 55 73 65 72 6e 61 6d 65 } 		$a_01_4 = {73 65 74 5f 55 73 65 72 6e 61 6d 65 } 		$a_01_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=24
 
}