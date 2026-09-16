rule Trojan_Win32_Ekstak_RO_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? fe f5 ff 89 45 fc e9 } 		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 68 c8 32 4c 00 e8 6d fe f5 ff 83 c4 04 89 45 fc e9 } 		$a_01_2 = {46 00 6c 00 61 00 70 00 70 00 69 00 6e 00 67 00 57 00 69 00 6e 00 67 00 73 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}