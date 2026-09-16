rule Backdoor_Win32_Lotok_GNA_MTB_2{
	meta:
		description = "Backdoor:Win32/Lotok.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d0 53 c6 45 d1 65 c6 45 d2 44 c6 45 d3 65 c6 45 d4 62 c6 45 d5 75 c6 45 d6 67 c6 45 d7 50 c6 45 d8 72 c6 45 d9 69 c6 45 da 76 c6 45 db 69 c6 45 dc 6c c6 45 dd 65 c6 45 de 67 c6 45 df 65 c6 45 e0 00 } 		$a_01_1 = {8b 55 08 03 55 fc 0f be 02 83 f0 19 8b 4d 08 03 4d fc 88 01 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}