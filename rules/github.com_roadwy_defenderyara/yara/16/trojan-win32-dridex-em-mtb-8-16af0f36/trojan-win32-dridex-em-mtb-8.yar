rule Trojan_Win32_Dridex_EM_MTB_8{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 89 4c 24 48 8b 54 24 20 89 54 24 4c 66 8b 74 24 56 66 83 f6 ff 8a 18 66 89 74 24 56 0f b6 c3 8b 7c 24 5c } 		$a_01_1 = {66 8b 4c 24 56 66 8b 54 24 56 2b 44 24 5c 66 09 d1 66 89 4c 24 56 c7 44 24 2c 5d 09 00 00 89 44 24 18 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}