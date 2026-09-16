rule Trojan_Win32_Emotet_DB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 fd 8b 44 24 68 8b 6c 24 24 83 c5 01 89 6c 24 24 03 54 24 58 03 54 24 5c 03 54 24 60 0f b6 14 02 8b 44 24 38 30 54 28 ff 3b 6c 24 70 0f 82 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}