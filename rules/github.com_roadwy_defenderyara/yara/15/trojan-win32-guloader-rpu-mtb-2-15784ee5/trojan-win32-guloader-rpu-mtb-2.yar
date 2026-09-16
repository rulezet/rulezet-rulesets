rule Trojan_Win32_Guloader_RPU_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 5d 00 3d bb 00 00 00 83 fe 2d } 		$a_01_1 = {81 fa e9 00 00 00 81 f9 a2 00 00 00 01 1c 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}