rule TrojanDownloader_Win32_Kuluoz_C_2{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3d 72 64 6c 26 75 3d 25 31 30 32 34 5b 5e 26 5d 26 61 3d 25 78 26 6b 3d 25 78 26 6e 3d 25 31 30 32 34 73 } 		$a_01_1 = {63 3d 72 75 6e 26 75 3d 25 31 30 32 34 73 } 		$a_01_2 = {25 31 30 32 34 5b 5e 3d 5d 3d 25 31 30 32 34 5b 5e 3b 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}