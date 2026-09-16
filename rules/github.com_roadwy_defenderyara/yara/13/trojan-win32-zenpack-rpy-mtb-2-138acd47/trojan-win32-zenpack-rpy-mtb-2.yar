rule Trojan_Win32_Zenpack_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 f1 58 00 00 00 89 d7 01 f7 81 c7 04 00 00 00 69 f1 58 00 00 00 01 f2 81 c2 2c 00 00 00 81 c1 01 00 00 00 8b 12 0f b7 37 31 d6 01 c6 81 f9 d4 01 00 00 89 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}