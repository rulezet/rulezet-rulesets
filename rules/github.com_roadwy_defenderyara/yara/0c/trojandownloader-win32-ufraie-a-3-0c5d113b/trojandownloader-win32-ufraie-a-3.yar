rule TrojanDownloader_Win32_Ufraie_A_3{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {76 09 30 04 08 40 3b 45 fc 72 f7 66 8b 01 66 3d 5a 4d 74 13 66 3d 4d 5a 74 0d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}