rule Trojan_Win32_Zenpak_RD_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 29 c2 8d 05 ?? ?? ?? ?? 31 30 31 2d ?? ?? ?? ?? 40 40 01 d0 8d 05 ?? ?? ?? ?? 89 38 40 8d 05 ?? ?? ?? ?? 31 18 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}