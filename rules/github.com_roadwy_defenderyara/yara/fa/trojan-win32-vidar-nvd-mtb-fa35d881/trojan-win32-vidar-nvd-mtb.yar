rule Trojan_Win32_Vidar_NVD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 65 44 43 00 47 ?? 49 33 32 2e 64 6c 6c 00 00 00 47 ?? 74 44 65 76 69 63 65 ?? 61 70 73 00 6f ?? 65 33 32 2e 64 6c 6c 00 00 00 43 ?? 43 } 		$a_01_1 = {70 77 70 78 78 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}