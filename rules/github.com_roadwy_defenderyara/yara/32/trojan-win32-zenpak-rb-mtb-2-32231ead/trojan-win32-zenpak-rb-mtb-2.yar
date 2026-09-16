rule Trojan_Win32_Zenpak_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e1 c7 41 08 00 00 00 00 c7 41 04 41 01 00 00 c7 01 c7 b6 ?? 00 8b 0d ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff d1 83 ec 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}