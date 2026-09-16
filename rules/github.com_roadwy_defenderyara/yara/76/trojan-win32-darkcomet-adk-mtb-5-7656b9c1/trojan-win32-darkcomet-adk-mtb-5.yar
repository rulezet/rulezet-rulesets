rule Trojan_Win32_DarkComet_ADK_MTB_5{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 68 00 04 00 00 8d 84 24 78 02 00 00 50 ff 74 24 } 		$a_01_1 = {48 6f 6f 6b 20 70 72 6f 63 65 64 75 72 65 20 68 61 73 20 62 65 65 6e 20 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } 		$a_01_2 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}