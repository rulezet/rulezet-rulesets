rule Trojan_Win32_Vidar_AMS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 44 24 [0-28] 30 04 29 45 3b 6b 04 0f 8c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}