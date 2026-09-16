rule TrojanDownloader_Win32_GuloaderCrypt_SN_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 32 0f 38 0b e3 0f 38 0b e3 83 c2 04 0f 38 01 e3 0f 38 01 e3 bb ?? ?? ?? ?? 0f 38 08 e3 0f 38 01 e3 31 1c 24 90 90 0f 38 01 e3 8f 04 01 90 90 0f 38 0b e3 40 0f 38 0b e3 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 40 90 90 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 be ?? ?? ?? ?? 0f 38 08 e3 0f 38 01 e3 39 f0 } 	condition:
		((#a_02_0  & 1)*4) >=4
 
}