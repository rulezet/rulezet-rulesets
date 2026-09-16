rule TrojanDownloader_Win32_ValleyRAT_EC_MTB{
	meta:
		description = "TrojanDownloader:Win32/ValleyRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 } 		$a_01_1 = {4e 00 54 00 55 00 53 00 45 00 52 00 2e 00 44 00 58 00 4d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}