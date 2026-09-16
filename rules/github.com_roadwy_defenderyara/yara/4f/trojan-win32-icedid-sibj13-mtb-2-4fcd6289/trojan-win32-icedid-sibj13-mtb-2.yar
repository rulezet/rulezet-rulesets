rule Trojan_Win32_IcedId_SIBJ13_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 74 6f 6f 64 2e 70 64 62 } 		$a_03_1 = {83 c5 04 0f [0-10] 81 fd ?? ?? ?? ?? 73 ?? [0-10] 90 18 [0-60] 8b 3d ?? ?? ?? ?? [0-20] 8b b4 2f ?? ?? ?? ?? [0-30] 81 c6 ?? ?? ?? ?? [0-10] 89 b4 ?? ?? ?? ?? [0-10] 83 c5 04 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}