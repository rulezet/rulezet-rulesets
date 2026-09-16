rule TrojanDownloader_Win32_Redosdru_F_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.F!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 } 		$a_01_1 = {c6 44 24 20 4d c6 44 24 21 6f c6 44 24 22 7a 88 54 24 23 88 4c 24 26 c6 44 24 27 2f c6 44 24 28 34 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}