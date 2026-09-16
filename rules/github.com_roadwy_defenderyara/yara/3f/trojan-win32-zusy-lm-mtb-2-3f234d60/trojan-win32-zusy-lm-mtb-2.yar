rule Trojan_Win32_Zusy_LM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 4c 00 00 00 b9 da 05 00 00 ba 85 3c de 9f 30 10 40 49 } 		$a_01_1 = {b0 c0 bc 40 0b b0 c0 bc 8b 00 97 37 37 37 34 c9 ba 69 37 a1 bc 47 0b a1 bc b3 07 03 37 37 37 1c ef bc 60 37 b0 ce bc 4e 33 b0 ce } 		$a_01_2 = {00 dc 02 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 00 00 00 00 00 00 00 00 00 80 00 00 00 30 15 00 00 66 00 00 00 dc 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}