rule Trojan_Win32_Redline_ME_MTB{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 55 ec 8b d7 d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d 60 41 84 00 0c 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}