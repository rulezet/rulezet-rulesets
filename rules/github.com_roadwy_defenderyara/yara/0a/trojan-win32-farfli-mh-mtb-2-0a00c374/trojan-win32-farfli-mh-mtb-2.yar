rule Trojan_Win32_Farfli_MH_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MH!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 40 8b cf 99 f7 f9 8a 1c 32 89 55 08 8d 04 32 89 45 f4 0f b6 c3 03 45 f8 99 f7 f9 8b 45 f4 89 55 f8 8d 0c 32 8a 14 32 88 10 8b 55 fc 88 19 8b 4d 0c 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 72 } 		$a_01_1 = {8b 45 08 8b 55 10 8b f9 83 45 10 04 8a 1c 30 0f b6 c3 03 02 03 45 fc 99 f7 ff 8a 04 32 89 55 fc 8d 3c 32 8b 55 08 ff 45 08 39 4d 08 88 04 32 88 1f 7c } 		$a_01_2 = {8b c3 33 d2 f7 75 10 8b 45 0c 88 1c 33 43 0f b6 04 02 89 07 83 c7 04 3b d9 7c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}