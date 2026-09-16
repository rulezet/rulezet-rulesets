rule TrojanDownloader_Win64_Small_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Small.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8d 0c 30 41 ff c0 80 34 ?? ?? 44 3b c0 72 f0 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}