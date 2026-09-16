rule Trojan_Win32_Vidar_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 c0 41 c8 17 6a 00 ff 15 } 		$a_01_1 = {0f a2 89 06 89 5e 04 89 4e 08 89 56 0c 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}