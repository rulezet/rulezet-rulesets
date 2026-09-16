rule Trojan_Win32_Zbot_BAC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 4d f0 8b 11 33 55 ec 8b 45 08 03 45 f0 89 10 e9 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}