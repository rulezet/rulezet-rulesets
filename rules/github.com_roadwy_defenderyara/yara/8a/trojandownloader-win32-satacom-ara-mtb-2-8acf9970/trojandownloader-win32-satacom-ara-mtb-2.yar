rule TrojanDownloader_Win32_Satacom_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Satacom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe c2 0f b6 d2 8b 4c ?? ?? 8d 04 0b 0f b6 d8 8b 44 ?? ?? 89 44 ?? ?? 89 4c ?? ?? 02 c8 0f b6 c1 8b 4d f8 8a 44 ?? ?? 30 04 ?? ?? 3b ?? fc 7c d0 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}