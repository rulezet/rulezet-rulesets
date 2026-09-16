rule Trojan_Win32_Redline_GJT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 e8 31 d2 83 ec 04 f7 74 24 3c c1 ea ?? 0f be 0c 16 69 c9 ?? ?? ?? ?? 89 c8 f7 ef 01 ca c1 f9 ?? c1 fa ?? 29 ca 8d 04 92 8d 14 42 30 14 2b 83 c5 ?? 39 6c 24 } 		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}