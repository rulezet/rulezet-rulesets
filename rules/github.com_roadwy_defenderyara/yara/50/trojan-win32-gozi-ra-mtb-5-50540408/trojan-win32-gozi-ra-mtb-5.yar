rule Trojan_Win32_Gozi_RA_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce 81 c2 d6 04 00 00 8b de 2b ca 2b dd 81 e9 68 da 00 00 83 c3 07 57 8d 3c 00 2b fa 8d 04 49 03 fe c1 e0 04 81 c1 28 c2 01 00 2b c6 05 d6 04 00 00 0f b7 c0 03 c7 03 c6 03 c8 5f 5e 8d 04 29 81 c1 1d e4 00 00 8d 04 40 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}