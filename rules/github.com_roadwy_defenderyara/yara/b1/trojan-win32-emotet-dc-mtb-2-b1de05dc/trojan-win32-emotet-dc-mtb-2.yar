rule Trojan_Win32_Emotet_DC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c2 89 d0 89 c2 c1 e2 04 01 c2 89 c8 29 d0 01 f8 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 dc 7c } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}