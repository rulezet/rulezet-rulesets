rule Trojan_Win32_Redline_MD_MTB{
	meta:
		description = "Trojan:Win32/Redline.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 10 8b 44 24 14 03 44 24 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 33 ?? 33 ?? 2b ?? 89 44 24 14 8b ?? c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d ?? ?? 75 0e } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}