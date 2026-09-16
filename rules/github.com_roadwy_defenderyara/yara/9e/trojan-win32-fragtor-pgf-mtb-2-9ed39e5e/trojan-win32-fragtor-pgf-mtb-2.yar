rule Trojan_Win32_Fragtor_PGF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f a3 c8 0f bd c9 8a 06 66 f7 d1 30 d8 88 cd 60 fe c0 88 1c 24 0f 9b c1 d0 c8 8d 8b ?? ?? ?? ?? e9 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}