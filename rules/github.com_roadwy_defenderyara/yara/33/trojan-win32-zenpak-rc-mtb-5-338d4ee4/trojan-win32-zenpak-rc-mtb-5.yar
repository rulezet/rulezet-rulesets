rule Trojan_Win32_Zenpak_RC_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 b8 07 00 00 00 29 c2 8d 05 ?? ?? ?? ?? 89 38 83 f0 04 42 89 c2 89 e8 50 8f 05 ?? ?? ?? ?? 31 c2 48 31 35 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}