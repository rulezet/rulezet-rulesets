rule TrojanSpy_Win32_IcedId_RAI_MTB{
	meta:
		description = "TrojanSpy:Win32/IcedId.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a } 		$a_01_1 = {81 c7 d4 2d 0a 01 03 c8 } 		$a_01_2 = {8a c3 80 ea 06 fe c8 f6 ea 89 7d 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}