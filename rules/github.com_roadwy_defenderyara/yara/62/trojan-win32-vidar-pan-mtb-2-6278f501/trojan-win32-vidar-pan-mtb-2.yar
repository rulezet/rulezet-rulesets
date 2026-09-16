rule Trojan_Win32_Vidar_PAN_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b f9 8b c7 c1 e0 04 03 45 e8 8b d7 89 45 fc 8b 45 f8 03 c7 c1 ea 05 03 55 ec 50 8d 4d fc c7 05 } 		$a_01_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 08 01 45 fc 83 6d fc 02 8b 45 fc 31 01 c9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}