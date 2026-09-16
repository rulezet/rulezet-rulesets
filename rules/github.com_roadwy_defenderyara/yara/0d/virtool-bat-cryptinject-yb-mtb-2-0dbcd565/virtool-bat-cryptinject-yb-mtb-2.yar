rule VirTool_BAT_CryptInject_YB_MTB_2{
	meta:
		description = "VirTool:BAT/CryptInject.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0c 16 11 0c 16 95 11 0d 16 95 61 9e 11 0c 17 11 0c 17 95 11 0d 17 95 5a 9e 11 0c 18 11 0c 18 95 11 0d 18 95 58 9e 11 0c 19 11 0c 19 95 11 0d 19 95 61 9e 11 0c 1a 11 0c 1a 95 11 0d 1a 95 5a 9e 11 0c 1b 11 0c 1b 95 11 0d 1b 95 58 9e 11 0c 1c 11 0c 1c 95 11 0d 1c 95 61 9e 11 0c 1d 11 0c 1d 95 11 0d 1d 95 5a 9e 11 0c 1e 11 0c 1e 95 11 0d 1e 95 58 9e 11 0c 1f 09 11 0c 1f 09 95 11 0d 1f 09 95 61 9e 11 0c 1f 0a 11 0c 1f 0a 95 11 0d 1f 0a 95 5a 9e 11 0c 1f 0b 11 0c 1f 0b 95 11 0d 1f 0b 95 58 9e 11 0c 1f 0c 11 0c 1f 0c 95 11 0d 1f 0c 95 61 9e 11 0c 1f 0d 11 0c 1f 0d 95 11 0d 1f 0d 95 5a 9e 11 0c 1f 0e 11 0c 1f 0e 95 11 0d 1f 0e 95 58 9e 11 0c 1f 0f 11 0c 1f 0f 95 11 0d 1f 0f 95 61 9e 1f 40 13 0e } 		$a_01_1 = {11 0c 11 14 11 0b 9e 11 0d 11 14 11 09 9e 11 09 1b 64 11 09 1f 1b 62 60 13 08 11 0a 19 64 11 0a 1f 1d 62 60 13 09 11 0b 1d 64 11 0b 1f 19 62 60 13 0a 11 08 1f 0b 64 11 08 1f 15 62 60 13 0b 11 14 17 58 13 14 } 		$a_01_2 = {03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}