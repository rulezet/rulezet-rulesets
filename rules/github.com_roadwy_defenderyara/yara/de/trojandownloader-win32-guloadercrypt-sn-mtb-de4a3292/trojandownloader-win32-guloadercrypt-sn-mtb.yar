rule TrojanDownloader_Win32_GuloaderCrypt_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f8 fc ff d0 fc e8 ?? ?? ?? ?? 83 75 ?? 00 b9 00 00 00 00 83 34 24 00 83 04 24 00 ff 34 0a fc fc 81 34 24 ?? ?? ?? ?? 83 34 24 00 83 6d ?? 00 8f 04 08 83 34 24 00 fc 83 e9 fc 83 45 ?? 00 ff 45 ?? ff 4d ?? 81 f9 ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}