rule Trojan_Win32_Zenpak_RK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 83 c2 04 83 f0 07 89 25 ?? ?? ?? ?? 48 83 e8 09 e8 2e 00 00 00 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}