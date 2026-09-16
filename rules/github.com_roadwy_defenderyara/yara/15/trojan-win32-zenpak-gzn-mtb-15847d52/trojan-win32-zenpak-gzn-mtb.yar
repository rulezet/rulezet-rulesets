rule Trojan_Win32_Zenpak_GZN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 31 d0 89 f0 50 8f 05 ?? ?? ?? ?? 48 01 c2 01 3d ?? ?? ?? ?? 29 c2 83 f0 01 42 89 d0 31 1d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}