rule Trojan_Win32_Dridex_AM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 44 24 14 04 8d 0c 40 2b 4c 24 18 ff 4c 24 24 0f b7 d1 8a 4c 24 0c } 		$a_01_1 = {8b c8 2b ce 2b cb 8b f1 0f b7 ca 03 cf } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}