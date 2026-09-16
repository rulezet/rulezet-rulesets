rule Trojan_Win32_Zenpak_GNA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 31 d0 31 c2 83 f2 ?? 31 c2 31 2d ?? ?? ?? ?? 31 d0 89 35 ?? ?? ?? ?? 31 c2 42 83 c0 ?? 89 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}