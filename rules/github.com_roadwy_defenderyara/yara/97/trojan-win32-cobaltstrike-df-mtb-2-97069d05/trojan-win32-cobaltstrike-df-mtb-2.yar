rule Trojan_Win32_Cobaltstrike_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 07 89 7d f8 8b 7d fc 88 04 3e 8b c7 8b 7d f8 88 0c 07 0f b6 04 06 8b 4d fc 03 c2 8b 7d f4 0f b6 c0 8a 04 08 32 04 1f 88 03 43 83 6d 0c 01 8b c1 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}