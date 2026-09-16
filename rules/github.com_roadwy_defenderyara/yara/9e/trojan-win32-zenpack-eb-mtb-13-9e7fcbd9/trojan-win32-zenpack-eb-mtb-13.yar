rule Trojan_Win32_Zenpack_EB_MTB_13{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb d7 89 45 } 		$a_01_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } 		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}