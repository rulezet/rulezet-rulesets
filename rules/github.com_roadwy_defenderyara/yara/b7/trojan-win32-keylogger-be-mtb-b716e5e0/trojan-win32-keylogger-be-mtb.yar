rule Trojan_Win32_KeyLogger_BE_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 15 8b 55 08 03 55 fc 8a 02 32 45 10 8b 4d 08 03 4d fc 88 01 eb } 		$a_01_1 = {6a 04 68 00 10 00 00 8b 55 f4 52 6a 00 ff 15 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}