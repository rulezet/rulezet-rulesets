rule Trojan_Win32_Redline_MB_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f7 c1 c1 0d f7 d6 33 fe c1 c8 17 f3 a4 81 f1 09 48 a0 61 33 1d ?? ?? ?? ?? 09 0d ?? ?? ?? ?? 2b c2 21 3d ?? ?? ?? ?? 2b fc c1 c2 1f 81 f3 ec 0c e1 82 0b 15 ?? ?? ?? ?? 09 35 ?? ?? ?? ?? 46 c1 ca 1a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}