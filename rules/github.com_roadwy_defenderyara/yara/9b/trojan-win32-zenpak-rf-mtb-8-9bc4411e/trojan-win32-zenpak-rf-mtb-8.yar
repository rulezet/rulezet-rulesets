rule Trojan_Win32_Zenpak_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 fb 01 fe 81 e6 ff 00 00 00 8b 3d ?? ?? ?? ?? 81 c7 9e f4 ff ff 89 3d ?? ?? ?? ?? 8b 7d ec 8a 1c 0f 8b 7d e4 32 1c 37 8b 75 e8 88 1c 0e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}