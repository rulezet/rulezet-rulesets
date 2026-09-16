rule TrojanDownloader_Win64_Small_ARA_MTB_2{
	meta:
		description = "TrojanDownloader:Win64/Small.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 4c 24 3b b2 62 30 4c 24 3c 32 d1 30 4c 24 3d 41 b0 3b 30 4c 24 3e 44 32 c1 30 4c 24 3f 41 b2 6d 30 4c 24 40 44 32 d1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}