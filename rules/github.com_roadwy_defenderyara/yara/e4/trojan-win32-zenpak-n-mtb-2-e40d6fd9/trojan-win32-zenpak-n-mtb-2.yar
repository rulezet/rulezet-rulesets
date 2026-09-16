rule Trojan_Win32_Zenpak_N_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 75 d0 32 0c 32 8b 55 ?? 88 0c 32 } 		$a_01_1 = {8b 12 0f b7 37 31 d6 01 ce } 		$a_01_2 = {8b 12 8b 3f 0f b7 1b 31 d3 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}