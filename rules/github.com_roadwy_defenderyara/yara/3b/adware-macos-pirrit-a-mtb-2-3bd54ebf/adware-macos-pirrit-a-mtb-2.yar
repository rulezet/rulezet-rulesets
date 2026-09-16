rule Adware_MacOS_Pirrit_A_MTB_2{
	meta:
		description = "Adware:MacOS/Pirrit.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {31 db 85 c0 0f 94 c3 48 8d 05 44 58 0d 00 48 89 95 50 ff ff ff 48 89 bd 58 ff ff ff 48 89 4d b0 48 89 75 c8 ff 24 d8 } 		$a_00_1 = {48 8d 15 33 f8 0c 00 48 8d 0d 4c f8 0c 00 4c 89 e7 48 89 de ff 55 80 48 8d 0d bc f7 0c 00 4c 89 e7 48 89 de 4c 89 fa ff 55 d0 48 8d 15 89 f7 0c 00 31 ff 4c 89 fe 48 8b 5d b0 48 89 d9 4d 89 e0 31 c0 e8 22 3c 05 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}