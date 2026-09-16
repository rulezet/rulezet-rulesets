rule Trojan_Win32_Guloader_RPR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f0 73 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}