rule Trojan_Win32_Zenpak_M_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 fa 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 01 ca 05 } 		$a_03_1 = {01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b 75 } 		$a_03_2 = {8a 1c 31 32 1c 17 8b 55 ?? 88 1c 32 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}