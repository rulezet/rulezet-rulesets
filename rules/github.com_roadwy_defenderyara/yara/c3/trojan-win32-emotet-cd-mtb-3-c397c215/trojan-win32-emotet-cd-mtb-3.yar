rule Trojan_Win32_Emotet_CD_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.CD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8a 5c 24 17 8a d4 8a c8 c0 ea 04 c0 e1 02 0a d1 8a 4c 24 16 88 16 8a d1 8a c4 46 c0 ea 02 c0 e0 04 0a d0 8b 44 24 10 88 16 46 c0 e1 06 0a cb 33 d2 88 0e 46 85 c0 } 		$a_01_1 = {6a 40 68 00 10 00 00 50 6a 00 ff 54 24 2c 8b 4c 24 58 8b 54 24 54 8b f0 51 52 56 ff 54 24 48 8b 44 24 64 8b 54 24 24 83 c4 0c 8d 4c 24 58 50 51 56 6a 00 6a 01 6a 00 52 ff 54 24 5c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}