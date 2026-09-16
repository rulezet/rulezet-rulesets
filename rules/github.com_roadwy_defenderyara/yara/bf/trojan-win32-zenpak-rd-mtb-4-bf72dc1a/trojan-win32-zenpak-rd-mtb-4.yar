rule Trojan_Win32_Zenpak_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 28 48 31 c2 83 c0 04 40 89 35 ?? ?? ?? ?? 29 c2 48 89 d0 01 3d ?? ?? ?? ?? b9 02 00 00 00 e2 c2 89 45 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}