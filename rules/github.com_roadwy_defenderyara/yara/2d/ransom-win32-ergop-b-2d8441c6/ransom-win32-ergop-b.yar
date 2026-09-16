rule Ransom_Win32_Ergop_B{
	meta:
		description = "Ransom:Win32/Ergop.B,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 34 53 56 57 bf 88 60 02 03 57 e8 ca bc ff ff 59 3d b3 01 00 00 76 17 81 7d d8 9b 4b 08 00 74 0e 81 7d d8 04 11 00 00 74 05 e8 } 		$a_01_1 = {55 8b ec 83 ec 3c 53 56 57 68 28 e8 02 03 e8 6d 03 ff ff 33 db 59 3d b3 01 00 00 0f 86 2b 01 00 00 81 7d d0 9b 4b 08 00 0f 84 1e 01 00 00 81 7d d0 04 11 00 00 0f 84 11 01 00 00 e8 00 ff ff ff } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100) >=100
 
}