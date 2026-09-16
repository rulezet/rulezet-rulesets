rule Trojan_Win32_Redline_GNR_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 06 83 c4 08 0f b6 0f 8b 74 24 10 03 c8 0f b6 c1 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}