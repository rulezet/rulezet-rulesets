rule Trojan_Win32_StopCrypt_RPX_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 89 5d f0 8b 45 e8 01 45 f0 8b 45 d0 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 cc 89 45 f8 8b 45 ec 31 45 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}