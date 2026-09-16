rule Trojan_Win32_Ursnif_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 55 2f 02 d3 f6 ea 8a d0 8b 45 1c 05 ?? ?? ?? ?? 89 45 24 fe c8 f6 e9 02 d0 02 55 47 30 14 31 83 3d ?? ?? ?? ?? 00 74 } 		$a_01_1 = {55 51 50 58 59 5d 59 5b c2 } 		$a_01_2 = {33 c0 0f af c8 8b c6 33 d2 f7 f1 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}