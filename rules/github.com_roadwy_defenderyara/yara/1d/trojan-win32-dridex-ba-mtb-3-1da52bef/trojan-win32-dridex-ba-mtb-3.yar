rule Trojan_Win32_Dridex_BA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.BA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 ca 89 4c 24 1c 2b c8 83 c1 25 89 4c 24 18 83 fe 09 74 1e 0f b6 c8 8a d3 6b c9 1a f6 da 2a d1 8b 4c 24 10 02 ca 89 4c 24 10 } 		$a_01_1 = {29 19 8d 50 29 83 e9 08 89 54 24 10 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}