rule Trojan_Win32_IcedId_SIBK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {75 77 75 6e 68 6b 71 6c 7a 6c 65 2e 64 6c 6c } 		$a_03_1 = {c1 e5 07 8b 4c 24 ?? c1 e9 ?? 89 f0 89 fe 89 cf ba ?? ?? ?? ?? 31 d7 89 eb 31 d3 41 b8 ?? ?? ?? ?? 44 21 c7 83 e1 ?? 09 f9 89 f7 89 c6 44 21 c3 81 e5 ?? ?? ?? ?? 09 dd 31 cd 45 0f be e9 89 e9 31 d1 b8 ?? ?? ?? ?? 21 c1 bb ?? ?? ?? ?? 21 dd 09 cd 44 89 e9 31 d1 21 c1 41 21 dd 41 09 cd 8b 4c 24 ?? ff c1 48 63 c1 48 03 44 24 ?? 41 31 ed 8b 54 24 ?? ff c2 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}