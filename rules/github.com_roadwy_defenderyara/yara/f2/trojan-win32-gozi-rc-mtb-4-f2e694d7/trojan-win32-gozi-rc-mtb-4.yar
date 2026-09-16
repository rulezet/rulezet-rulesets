rule Trojan_Win32_Gozi_RC_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 14 1b 2b d1 81 c2 e4 87 ff ff 0f b6 c2 6b c8 3e 8b c6 89 54 24 14 2b c3 05 e4 87 ff ff 8a d0 89 44 24 10 a3 d4 69 0d 01 2a d1 88 54 24 1b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}