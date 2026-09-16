rule Trojan_BAT_SnakeKeylogger_RS_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 4b 00 00 0a 1f 10 28 4c 00 00 0a 9c 1e 13 09 38 f5 f7 ff ff } 		$a_01_1 = {11 06 07 8e 69 fe 04 13 07 11 07 2d 15 11 0a 20 a9 00 00 00 94 20 0c 70 00 00 59 13 09 38 c3 f7 ff ff } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}