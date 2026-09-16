rule Trojan_Win32_Zenpak_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 ?? ?? ?? ?? 31 d0 83 c2 09 83 c0 08 eb 05 e8 ?? ?? ?? ?? 29 c2 31 35 ?? ?? ?? ?? b8 03 00 00 00 89 3d ?? ?? ?? ?? 83 c0 06 01 d0 89 d8 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}