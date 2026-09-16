rule Trojan_Win32_Redline_ME_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 60 81 6c 24 38 27 ea 21 11 81 6c 24 28 6b 07 bb 7c 81 44 24 28 4a ed 6f 20 81 6c 24 38 17 ff 9e 54 b8 ce 53 c0 1c f7 64 24 40 8b 44 24 40 81 6c 24 7c 4a e2 62 25 81 6c 24 20 9c 3b df 75 81 6c 24 38 00 ac 9a 59 b8 9a 7b f6 4a f7 64 24 20 8b 44 24 20 81 6c 24 28 b5 d6 af 6e 81 44 24 68 1b ee 2f 65 b8 22 cf 72 1e } 		$a_01_1 = {55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } 		$a_01_2 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 57 } 		$a_01_3 = {47 65 74 43 50 49 6e 66 6f } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}