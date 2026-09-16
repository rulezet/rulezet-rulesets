rule Trojan_Win32_Zenpak_GNS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 40 8d 05 ?? ?? ?? ?? 89 18 83 c2 ?? 31 c2 4a 31 2d ?? ?? ?? ?? 29 d0 31 d0 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 83 e8 ?? 31 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}