rule Trojan_Win32_Redline_GTC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 83 3d ?? ?? ?? ?? 20 75 13 90 0a 46 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 } 		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}