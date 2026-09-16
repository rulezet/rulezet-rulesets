rule Trojan_BAT_SnakeKeylogger_SML_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4e 66 6c 7a 70 74 75 6d 6d 71 } 		$a_81_1 = {24 61 30 33 66 31 35 37 36 2d 38 35 38 30 2d 34 65 64 35 2d 39 32 35 32 2d 30 62 38 31 37 32 38 34 38 38 65 38 } 		$a_00_2 = {06 07 a3 02 00 00 01 28 05 00 00 06 dd 06 00 00 00 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}