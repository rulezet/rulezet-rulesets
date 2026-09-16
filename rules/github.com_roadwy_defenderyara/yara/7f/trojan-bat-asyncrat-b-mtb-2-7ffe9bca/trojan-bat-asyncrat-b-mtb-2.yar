rule Trojan_BAT_AsyncRAT_B_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 07 00 00 70 0a 73 17 00 00 0a 73 18 00 00 0a 0b 07 6f 19 00 00 0a 72 c0 dd 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 6f 19 00 00 0a 72 22 de 0f 70 7e 01 00 00 04 28 03 00 00 06 6f 1a 00 00 0a 26 07 17 6f 1b 00 00 0a 07 17 8d 14 00 00 01 } 		$a_01_1 = {38 35 30 31 64 31 37 32 2d 31 65 62 62 2d 34 36 31 33 2d 38 37 61 34 2d 65 65 66 37 66 32 35 34 36 61 32 37 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}