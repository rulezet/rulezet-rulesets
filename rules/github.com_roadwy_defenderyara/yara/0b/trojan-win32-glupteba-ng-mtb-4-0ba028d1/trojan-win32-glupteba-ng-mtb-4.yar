rule Trojan_Win32_Glupteba_NG_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 d2 01 d3 5e 83 ec 04 89 14 24 5a 41 bb ?? ?? ?? ?? 83 ec 04 89 1c 24 8b 1c 24 83 c4 04 53 8b 14 24 83 c4 04 81 f9 06 98 00 01 75 b4 } 		$a_01_1 = {c7 04 24 44 95 40 00 41 01 d2 68 00 90 40 00 5e 01 c0 8b 1c 24 83 c4 04 e8 45 00 00 00 8b 34 24 83 c4 04 50 8b 0c 24 83 c4 04 5b 09 ca } 		$a_01_2 = {52 65 6d 6f 74 65 20 41 63 63 65 73 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}