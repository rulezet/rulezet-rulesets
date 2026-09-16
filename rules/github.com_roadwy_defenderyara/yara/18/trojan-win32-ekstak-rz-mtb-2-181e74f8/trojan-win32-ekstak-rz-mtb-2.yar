rule Trojan_Win32_Ekstak_RZ_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 57 68 21 cf 64 00 e8 f4 73 fb ff 8b f0 e9 } 		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 68 84 22 4c 00 e8 ?? ec f5 ff 83 c4 04 89 45 fc e9 } 		$a_01_2 = {55 8b ec 83 ec 0c 53 56 57 e8 82 ec f5 ff 89 45 fc e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}