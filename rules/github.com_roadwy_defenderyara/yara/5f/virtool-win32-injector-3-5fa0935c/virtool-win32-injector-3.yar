rule VirTool_Win32_Injector_3{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f bf d0 89 15 68 90 40 00 8b 4d d8 81 c1 aa 38 00 00 a1 64 90 40 00 99 f7 f9 89 55 fc 0f bf 0d 7e 90 40 00 81 c1 a7 00 00 00 8b 45 fc 99 } 		$a_01_1 = {0f 9d c2 83 e2 01 0b 55 fc 74 2f 8b 0d 64 90 40 00 81 c1 21 0d 00 00 a1 84 90 40 00 99 f7 f9 0f bf 0d 8a 90 40 00 3b d1 7d 10 0f be 05 91 90 40 00 33 05 68 90 40 00 89 45 fc a1 84 90 40 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=10
 
}