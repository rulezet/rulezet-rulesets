rule Trojan_Win32_SmokeLoader_RPY_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 0e fc ff ff 33 c6 85 11 fc ff ff 6e c6 85 06 fc ff ff 54 c6 85 13 fc ff ff 70 c6 85 0f fc ff ff 32 c6 85 01 fc ff ff 72 c6 85 09 fc ff ff 6c c6 85 15 fc ff ff 68 c6 85 14 fc ff ff 73 c6 85 04 fc ff ff 74 c6 85 12 fc ff ff 61 c6 85 10 fc ff ff 53 c6 85 03 fc ff ff 61 c6 85 18 fc ff ff 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}