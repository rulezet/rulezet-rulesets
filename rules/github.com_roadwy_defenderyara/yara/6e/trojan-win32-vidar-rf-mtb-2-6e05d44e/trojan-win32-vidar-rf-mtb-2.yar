rule Trojan_Win32_Vidar_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 01 88 06 88 11 0f b6 0e 0f b6 c2 03 c8 0f b6 c1 8b 8d ?? ?? ff ff 0f b6 84 05 ?? ?? ff ff 30 04 0f 47 3b bd 3c f0 ff ff 72 b8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}