rule Trojan_Win64_KeyLogger_NK_MTB_2{
	meta:
		description = "Trojan:Win64/KeyLogger.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 48 41 b9 01 00 00 00 48 89 44 24 20 48 8d 15 7c 68 00 00 48 8b c3 45 33 c0 48 c7 c1 02 00 00 80 ff 15 89 f2 00 00 85 c0 74 37 } 		$a_01_1 = {c7 44 24 40 08 02 00 00 48 89 44 24 20 48 8d 15 91 68 00 00 48 8b c6 45 33 c0 ff 15 15 f2 00 00 48 8b 4c 24 48 8b d8 49 8b c6 ff 15 05 f2 00 00 48 8b cf } 		$a_01_2 = {6b 65 79 6c 6f 67 67 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}