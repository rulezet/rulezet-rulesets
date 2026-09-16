rule TrojanDownloader_Win32_Raemnk_A{
	meta:
		description = "TrojanDownloader:Win32/Raemnk.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {3a 00 5c 00 47 00 45 00 52 00 41 00 5c 00 62 00 69 00 6e 00 5c 00 } 		$a_00_1 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 45 00 4e 00 56 00 49 00 4f 00 5c 00 62 00 69 00 6e 00 5c 00 } 		$a_03_2 = {6c 54 ff 2a 23 4c ff 08 08 00 06 ?? 00 24 ?? 00 0d 44 00 ?? 00 6b 4a ff f4 ff c6 32 08 00 58 ff 50 ff 54 ff 4c ff 35 5c ff 1c af 00 00 53 3a 6c ff ?? 00 4e 5c ff } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}