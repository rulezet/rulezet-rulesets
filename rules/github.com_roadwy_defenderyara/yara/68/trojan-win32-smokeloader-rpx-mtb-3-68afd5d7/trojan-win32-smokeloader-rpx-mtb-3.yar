rule Trojan_Win32_SmokeLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d f8 fb ff ff 30 04 39 83 fb 0f 75 1f 56 8d 85 fc fb ff ff 50 56 56 56 56 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}