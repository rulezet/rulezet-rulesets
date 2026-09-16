rule PWS_Win32_Zbot{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 11 8b 74 24 38 8b d0 2b f2 8a 10 88 14 06 40 4f 75 f7 8b 01 8b 4c 24 1c 01 44 24 38 83 c1 08 83 39 00 89 4c 24 1c 8d 41 fc 89 4c 24 34 0f 85 1c ff ff ff 8b 44 24 40 6a 00 50 c7 40 01 10 67 41 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}