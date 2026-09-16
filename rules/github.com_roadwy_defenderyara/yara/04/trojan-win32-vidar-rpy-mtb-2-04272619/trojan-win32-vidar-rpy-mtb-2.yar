rule Trojan_Win32_Vidar_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 99 f7 7d 0c 03 55 0c 8b c2 99 f7 7d 0c 8b c2 5d c3 } 		$a_01_1 = {c6 45 d8 61 c6 45 d9 67 c6 45 da 6a c6 45 db 76 c6 45 dc 33 c6 45 dd 76 c6 45 de 33 c6 45 df 6a c6 45 e0 76 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}