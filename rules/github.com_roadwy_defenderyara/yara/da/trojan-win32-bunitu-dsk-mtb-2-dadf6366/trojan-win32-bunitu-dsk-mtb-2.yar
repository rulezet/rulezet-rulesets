rule Trojan_Win32_Bunitu_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitu.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 38 1b 55 00 8b c0 8b ca 8b c0 a3 54 1b 55 00 8b c0 8b 3d 54 1b 55 00 33 f9 89 3d 54 1b 55 00 8b c0 a1 54 1b 55 00 c7 05 38 1b 55 00 00 00 00 00 01 05 38 1b 55 00 8b 0d 48 1b 55 00 8b 15 38 1b 55 00 89 11 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}