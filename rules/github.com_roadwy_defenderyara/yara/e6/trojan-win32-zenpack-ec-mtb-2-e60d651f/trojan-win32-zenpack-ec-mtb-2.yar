rule Trojan_Win32_Zenpack_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 6a 00 2d 83 11 00 00 50 ff 14 24 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 74 bb } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}