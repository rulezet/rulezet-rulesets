rule TrojanDownloader_Win32_Banload_VN{
	meta:
		description = "TrojanDownloader:Win32/Banload.VN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 68 74 6d 6c [0-10] 43 3a 5c 57 49 4e 44 4f 57 53 [0-20] 66 69 6c 65 [0-02] 2e 65 78 65 [0-10] 6d 64 69 74 [0-02] 2e 65 78 65 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}