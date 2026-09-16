rule TrojanDownloader_Win64_Convagent_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Convagent.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 30 49 83 fa 10 49 0f 43 c3 0f b6 04 38 30 01 ff c2 48 ff c7 48 ff c1 49 ff c8 75 d4 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}