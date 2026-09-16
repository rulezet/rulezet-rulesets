rule Trojan_Win32_Cryptinject_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/Cryptinject.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 85 d4 ef ff ff 8b 9d d0 ef ff ff c0 e0 06 08 85 d5 ef ff ff 8a 85 d6 ef ff ff 88 04 1f 81 3d bc ff 16 04 0e 06 00 00 75 } 		$a_01_1 = {a1 34 89 14 04 8a 4c 18 01 88 8d d7 ef ff ff 8a 4c 18 02 8a 44 18 03 8a d8 80 e3 f0 c0 e3 02 81 3d bc ff 16 04 d3 0b 00 00 88 8d d5 ef ff ff 88 85 d4 ef ff ff 75 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}