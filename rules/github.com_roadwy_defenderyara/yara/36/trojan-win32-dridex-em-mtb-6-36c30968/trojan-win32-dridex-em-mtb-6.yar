rule Trojan_Win32_Dridex_EM_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 0f b6 c1 83 f8 6a 89 44 24 1c } 		$a_01_1 = {8a 08 8b 44 24 50 25 0c 69 3a 7d 89 44 24 50 c7 44 24 54 00 00 00 00 0f b6 c1 3d b8 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}