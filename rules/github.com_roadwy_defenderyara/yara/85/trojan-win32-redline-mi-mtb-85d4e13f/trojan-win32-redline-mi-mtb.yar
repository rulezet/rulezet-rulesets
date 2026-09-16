rule Trojan_Win32_Redline_MI_MTB{
	meta:
		description = "Trojan:Win32/Redline.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 03 45 cc 89 45 f0 33 45 dc 31 45 fc 8b 45 fc 29 45 f8 81 c3 ?? ?? ?? ?? 89 5d ec 4f 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}