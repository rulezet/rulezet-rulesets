rule Trojan_Win32_ICLoader_RD_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {d0 16 66 00 83 c4 04 03 ?? 89 ?? d0 16 66 00 e8 ?? ?? 00 00 e9 } 		$a_01_1 = {62 00 75 00 72 00 6e 00 69 00 6e 00 67 00 73 00 74 00 75 00 64 00 69 00 6f 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}