rule Trojan_Win32_Qakbot_AR_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 f5 30 de bc e8 98 20 0b 14 34 0a eb ba 64 a1 97 57 2c 61 4c 37 ad } 		$a_01_1 = {19 36 00 0b 97 37 ff 47 20 3e 8b 06 } 		$a_01_2 = {83 74 d0 38 5f 74 da b9 51 a2 4e 4f 53 ed 38 5c 5f ef b9 5d 62 de 2e 08 7a 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}