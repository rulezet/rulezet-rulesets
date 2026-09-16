rule Trojan_Win32_SmokeLoader_RG_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 85 54 fe ff ff dd 8a 30 3f c7 85 5c fe ff ff 1a a0 a6 15 c7 85 8c fe ff ff cb 2e 4a 32 c7 85 cc fd ff ff 37 5f 18 1f c7 85 d4 fd ff ff 3f 18 79 15 c7 85 14 fe ff ff 42 ac ee 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}