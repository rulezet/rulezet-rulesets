rule Trojan_Win32_BladaInjector_MTB_3{
	meta:
		description = "Trojan:Win32/BladaInjector!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 ea 00 00 0a 00 16 28 eb 00 00 0a 00 73 01 00 00 06 28 ec 00 00 0a 00 2a } 		$a_01_1 = {6f f4 00 00 0a 28 0b 02 00 06 13 0b 11 0b 8e 69 8d 7a 00 00 01 13 0c 16 13 10 2b 19 } 		$a_01_2 = {28 f6 00 00 0a 6f f7 00 00 0a 16 9a 13 0d 11 0d 1d 8d 0a 00 00 01 25 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}