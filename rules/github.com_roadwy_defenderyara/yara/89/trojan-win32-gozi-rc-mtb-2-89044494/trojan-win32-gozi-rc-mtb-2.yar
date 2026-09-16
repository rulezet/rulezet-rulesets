rule Trojan_Win32_Gozi_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 e0 02 c3 0f b6 c8 8b 02 d3 c8 83 c2 04 33 c7 2b c3 89 42 fc 4b 75 e7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}