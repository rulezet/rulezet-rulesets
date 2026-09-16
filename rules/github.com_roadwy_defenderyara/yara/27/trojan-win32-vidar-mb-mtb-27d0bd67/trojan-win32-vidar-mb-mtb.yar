rule Trojan_Win32_Vidar_MB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8d 50 01 8b 45 ec 01 d0 0f b6 84 05 1e 8f ff ff 88 85 2f bb ff ff 8b 45 f0 8d 50 01 8b 45 ec 01 c2 8b 45 f4 83 e8 01 2b 45 ec 0f b6 84 05 1e 8f ff ff 88 84 15 1e 8f ff ff 8b 45 f4 83 e8 01 2b 45 ec 0f b6 95 2f bb ff ff 88 94 05 1e 8f ff ff 83 45 ec 01 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}