rule Trojan_Win32_Copak_DR_MTB{
	meta:
		description = "Trojan:Win32/Copak.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c1 f2 b6 21 03 81 c0 9f e8 0e eb e8 [0-04] 81 c1 2a 21 91 32 31 33 43 39 d3 75 } 		$a_01_1 = {21 d2 01 d1 81 c1 31 6f fc 73 5e 09 ca 29 d2 47 29 d1 4a 09 ca 81 ff 4e cc 00 01 75 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}