rule TrojanDownloader_Win32_Satacom_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Satacom.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 04 39 88 04 3b 47 3b 7d 18 72 cd } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}