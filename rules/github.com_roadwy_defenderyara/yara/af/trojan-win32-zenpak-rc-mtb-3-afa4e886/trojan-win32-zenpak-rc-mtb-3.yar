rule Trojan_Win32_Zenpak_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 ba 09 00 00 00 83 e8 06 42 83 c0 03 01 2d ?? ?? ?? ?? 83 ea 01 4a 8d 05 ?? ?? ?? ?? 31 38 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}