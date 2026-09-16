rule Trojan_Win32_Emotet_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 0f 8d 7f 04 33 cb 0f b6 c1 66 89 02 8b c1 c1 e8 08 8d 52 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 c1 e9 08 45 66 89 42 fc 0f b6 c1 66 89 42 fe 3b ee 72 } 		$a_00_1 = {8b 45 3c 8b 7c 24 10 89 44 24 30 8b 5c 28 78 03 dd 8b 43 1c 8b 4b 20 03 c5 89 44 24 2c 03 cd 8b 43 24 03 c5 89 4c 24 24 89 44 24 28 eb } 		$a_81_2 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}