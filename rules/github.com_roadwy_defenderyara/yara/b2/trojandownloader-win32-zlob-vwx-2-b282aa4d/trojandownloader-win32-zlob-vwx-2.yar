rule TrojanDownloader_Win32_Zlob_VWX_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.VWX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 85 f0 fe ff ff 47 c6 85 f1 fe ff ff 45 c6 85 f2 fe ff ff 54 } 		$a_01_1 = {6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00 66 65 65 64 00 70 6c 65 6d 00 } 		$a_01_2 = {5f 52 45 44 44 5f 00 } 		$a_01_3 = {25 73 5c 6a 65 65 25 73 25 64 2e 65 78 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}