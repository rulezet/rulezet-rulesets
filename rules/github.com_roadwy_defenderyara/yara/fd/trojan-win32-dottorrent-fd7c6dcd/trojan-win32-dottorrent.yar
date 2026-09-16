rule Trojan_Win32_DotTorrent{
	meta:
		description = "Trojan:Win32/DotTorrent,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 61 6e 61 67 65 72 00 44 6f 77 6e 6c 6f 61 64 20 41 ?? 4d 61 6e 61 67 65 72 00 ?? ?? ?? 5c 61 ?? 6d 61 6e 61 67 65 72 2e 65 78 65 00 } 		$a_03_1 = {73 6f 66 74 2f 69 6e 73 74 61 6c 6c 2d 90 09 03 00 2f 6d 90 0f 01 00 } 		$a_01_2 = {2e 74 6f 72 72 65 6e 74 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}