rule Trojan_Win32_Azorult_CB_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 8b 4d 08 8b 45 0c 83 65 fc 00 89 01 8b 45 0c 33 45 fc 89 45 fc 8b 45 fc 89 01 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}