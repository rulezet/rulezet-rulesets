rule TrojanDownloader_Win32_Agent_ZDK_3{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 64 00 61 00 72 00 65 00 61 00 6c 00 32 00 30 00 31 00 30 00 2e 00 70 00 69 00 73 00 65 00 6d 00 2e 00 73 00 75 00 2f 00 69 00 6d 00 67 00 6c 00 6f 00 67 00 2e 00 65 00 78 00 65 00 } 		$a_01_1 = {c7 45 fc 07 00 00 00 68 1c 2c 40 00 e8 f1 06 00 00 0f bf c8 85 c9 75 48 c7 45 fc 08 00 00 00 ba 1c 2c 40 00 8d 4d 90 ff 15 98 10 40 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*10) >=10
 
}