rule Trojan_Win32_ValleyRat_AVA_MTB_2{
	meta:
		description = "Trojan:Win32/ValleyRat.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 68 c8 51 41 00 8b 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 00 68 ec 51 41 00 68 20 52 41 00 68 30 52 41 00 6a 00 ff 15 } 		$a_01_1 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 63 72 65 61 74 65 64 20 73 63 68 65 64 75 6c 65 64 20 74 61 73 6b } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}