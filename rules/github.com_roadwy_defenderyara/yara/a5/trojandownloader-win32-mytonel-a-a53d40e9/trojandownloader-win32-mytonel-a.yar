rule TrojanDownloader_Win32_Mytonel_A{
	meta:
		description = "TrojanDownloader:Win32/Mytonel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 fd 00 fe 0f [0-10] 81 ?? 00 17 00 00 } 		$a_00_1 = {33 64 69 6d 37 30 30 2e 44 4c 4c } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}