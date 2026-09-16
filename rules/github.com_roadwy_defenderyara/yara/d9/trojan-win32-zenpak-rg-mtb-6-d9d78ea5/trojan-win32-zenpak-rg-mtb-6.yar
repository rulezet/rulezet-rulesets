rule Trojan_Win32_Zenpak_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 31 c2 8d 05 ?? ?? ?? ?? 89 20 e8 25 00 00 00 c3 89 c2 83 f0 06 8d 05 ?? ?? ?? ?? 89 38 42 ba 0a 00 00 00 42 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? ff e0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}