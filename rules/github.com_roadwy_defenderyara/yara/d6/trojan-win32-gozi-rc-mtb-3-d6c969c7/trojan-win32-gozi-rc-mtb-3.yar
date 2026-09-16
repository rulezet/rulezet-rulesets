rule Trojan_Win32_Gozi_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 58 14 8b ce 81 f1 0e 15 00 00 42 6b d2 28 03 d8 0f b7 c9 81 f6 5c 5f b2 69 03 da 89 4d f4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}