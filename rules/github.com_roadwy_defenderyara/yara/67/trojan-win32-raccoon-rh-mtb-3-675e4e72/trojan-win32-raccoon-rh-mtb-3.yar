rule Trojan_Win32_Raccoon_RH_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 0f 00 00 c7 04 24 f0 43 03 00 75 08 6a 00 ff 15 ?? ?? ?? ?? 56 83 44 24 04 0d a1 ?? ?? ?? ?? 0f af 44 24 04 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 75 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}