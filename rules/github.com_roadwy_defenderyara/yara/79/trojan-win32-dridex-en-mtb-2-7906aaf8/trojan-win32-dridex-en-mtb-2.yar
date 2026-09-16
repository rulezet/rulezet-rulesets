rule Trojan_Win32_Dridex_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b c8 8b 44 24 14 8b 3f 02 c7 89 7c 24 24 f6 d8 0f b6 fb 8a f8 89 4c 24 10 } 		$a_02_1 = {89 07 b0 ce 2a 44 24 0f 83 c7 04 2a 05 ?? ?? ?? ?? 2a 44 24 10 02 d8 89 7c 24 1c 83 6c 24 20 01 8b 44 24 14 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}