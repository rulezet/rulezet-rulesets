rule Trojan_BAT_Loki_A_MTB_2{
	meta:
		description = "Trojan:BAT/Loki.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 1c 00 00 01 13 14 11 09 28 2d 00 00 0a 16 11 14 16 1a 28 2e 00 00 0a 11 0a 28 2d 00 00 0a 16 11 14 1a 1a 28 2e 00 00 0a 11 0b 28 2d 00 00 0a 16 11 14 1e 1a } 		$a_01_1 = {37 63 66 63 33 33 63 32 2d 38 66 66 63 2d 34 35 32 61 2d 39 37 65 66 2d 61 66 30 66 63 62 63 38 32 61 66 34 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}