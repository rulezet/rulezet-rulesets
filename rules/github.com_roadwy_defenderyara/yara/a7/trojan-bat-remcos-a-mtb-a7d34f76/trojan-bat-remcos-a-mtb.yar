rule Trojan_BAT_Remcos_A_MTB{
	meta:
		description = "Trojan:BAT/Remcos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 72 0f 00 00 70 6f 1c 00 00 0a 14 17 8d 01 00 00 01 25 16 02 a2 28 22 00 00 06 2a } 		$a_01_1 = {7e 02 00 00 04 2d 1e 72 21 00 00 70 d0 0b 00 00 02 28 3f 00 00 06 6f 32 00 00 0a 73 33 00 00 0a 80 02 00 00 04 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}