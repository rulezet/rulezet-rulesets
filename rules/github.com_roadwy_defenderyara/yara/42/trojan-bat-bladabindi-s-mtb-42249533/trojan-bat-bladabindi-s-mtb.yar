rule Trojan_BAT_Bladabindi_S_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.S!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 2a 8b 35 88 2c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 24 20 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d a0 2c 41 00 76 c9 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}