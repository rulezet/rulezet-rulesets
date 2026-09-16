rule TrojanDownloader_Win32_Chengtot_B{
	meta:
		description = "TrojanDownloader:Win32/Chengtot.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 00 00 00 [0-12] 74 00 [0-12] 70 00 [0-12] 3a 00 [0-12] 2f 00 [0-12] 77 00 [0-12] 6f 00 [0-12] 6c 00 [0-12] 63 00 [0-12] 6d 00 [0-12] 61 00 [0-12] 3f 00 [0-12] 71 00 [0-12] 3d 00 [0-20] 73 65 78 20 64 6f 77 6e 6c 6f 61 64 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}