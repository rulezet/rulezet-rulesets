rule Trojan_Win32_LummaStealer_NIT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 75 00 8d 4e bf 66 83 f9 1a 73 03 83 ce 20 0f b7 0b 8d 41 bf 66 83 f8 1a 73 03 83 c9 20 66 85 f6 74 0b 83 c5 02 83 c3 02 66 39 ce 74 d1 } 		$a_01_1 = {21 cf 09 f7 21 d7 09 c2 31 fa 80 c2 da 88 54 04 ef 40 49 83 f8 27 75 d7 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}