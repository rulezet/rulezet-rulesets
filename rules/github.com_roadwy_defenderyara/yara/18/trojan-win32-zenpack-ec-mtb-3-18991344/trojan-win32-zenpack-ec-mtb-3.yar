rule Trojan_Win32_Zenpack_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ea 05 89 e8 50 8f 05 ?? ?? ?? ?? e9 e6 f5 ff ff c3 8d 05 ?? ?? ?? ?? 31 18 01 d0 31 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 3d ?? ?? ?? ?? eb d1 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}