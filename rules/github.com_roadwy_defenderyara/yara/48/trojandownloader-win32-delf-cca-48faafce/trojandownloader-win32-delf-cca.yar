rule TrojanDownloader_Win32_Delf_CCA{
	meta:
		description = "TrojanDownloader:Win32/Delf.CCA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 28 00 04 00 00 "
		
	strings :
		$a_02_0 = {ac fe c8 eb 01 ?? c0 c0 98 eb 01 ?? 2a c1 f9 34 08 eb 01 ?? f9 02 c1 eb 01 ?? f9 f8 eb 01 ?? c0 c0 72 fe c8 34 01 f8 2a c1 f8 eb 01 ?? 02 c1 2c 70 aa e2 cc } 		$a_00_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 47 61 6d 65 53 65 74 75 70 2e 65 78 65 } 		$a_00_2 = {5c 6b 61 73 70 65 72 73 6b 79 2e 65 78 65 20 2f 69 } 		$a_00_3 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 61 20 61 75 74 6f 72 75 6e 2e 69 6e 66 } 	condition:
		((#a_02_0  & 1)*20+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}