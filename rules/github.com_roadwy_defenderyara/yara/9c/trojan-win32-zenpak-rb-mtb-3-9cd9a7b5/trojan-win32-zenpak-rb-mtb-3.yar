rule Trojan_Win32_Zenpak_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 f0 5c 00 00 00 89 d7 01 f7 81 c7 34 00 00 00 8b 37 69 f8 5c 00 00 00 01 fa 81 c2 30 00 00 00 0f b7 12 31 f2 01 ca 05 01 00 00 00 3d 27 03 00 00 89 d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}