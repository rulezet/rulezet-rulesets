rule Trojan_Win32_Vidar_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 4d f4 8d 14 07 31 55 fc } 		$a_01_1 = {8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}