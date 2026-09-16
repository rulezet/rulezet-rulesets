rule Trojan_Win32_Raccrypt_GW_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 00 01 00 00 c7 [0-06] 57 78 d1 51 c7 [0-06] 0b 4c 1b 7e c7 [0-06] dd 0b fa 64 c7 [0-06] cf 72 b2 3d c7 [0-06] e9 0e 74 64 c7 [0-06] a9 53 5d 16 c7 [0-06] 05 c8 4e 43 c7 [0-06] 82 2d 68 68 } 	condition:
		((#a_02_0  & 1)*10) >=1
 
}