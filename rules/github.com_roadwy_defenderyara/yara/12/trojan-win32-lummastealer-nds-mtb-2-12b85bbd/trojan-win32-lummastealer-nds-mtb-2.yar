rule Trojan_Win32_LummaStealer_NDS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 5a 4a 76 73 73 2d 2d } 		$a_01_1 = {f7 d5 21 eb 09 f3 f7 d0 21 c7 09 cf 89 dd 0f a4 fd 01 8d 34 3f f7 d5 f7 d6 01 fe 11 dd } 		$a_01_2 = {0f b7 c0 89 c6 f7 d6 0f b7 c9 21 ce f7 d1 21 c1 31 c0 39 ce 0f 94 c0 8b 4c 24 04 } 		$a_01_3 = {31 d1 69 c9 93 01 00 01 0f be 50 01 31 ca 69 ca 93 01 00 01 0f be 50 02 31 ca 69 ca 93 01 00 01 0f be 50 03 83 c0 04 31 ca } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}