rule Trojan_Win32_Zusy_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 41 02 00 00 c7 45 fc 03 1b 00 00 8b 45 f4 03 45 fc 89 45 f4 c7 45 f0 00 00 00 00 8b 4d fc 03 4d f4 89 4d fc 8b 55 f0 2b 55 f4 89 55 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}