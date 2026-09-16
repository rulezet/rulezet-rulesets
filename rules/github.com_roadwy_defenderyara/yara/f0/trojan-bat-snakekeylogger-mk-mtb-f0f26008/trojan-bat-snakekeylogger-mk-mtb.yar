rule Trojan_BAT_SnakeKeylogger_MK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } 		$a_03_1 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 [0-16] 53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}