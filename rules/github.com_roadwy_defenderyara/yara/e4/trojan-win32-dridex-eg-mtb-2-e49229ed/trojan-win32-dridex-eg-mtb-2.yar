rule Trojan_Win32_Dridex_EG_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EG!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 57 fe 8b da 33 d2 2b d8 1b ea 0f b7 c6 99 2b d8 1b ea 03 cb 8b 5c 24 1c 13 dd 8b 6c 24 10 } 		$a_01_1 = {0f b7 d6 be 0e 00 00 00 2b f2 2b f0 8b 45 00 05 0c 46 05 01 89 45 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}