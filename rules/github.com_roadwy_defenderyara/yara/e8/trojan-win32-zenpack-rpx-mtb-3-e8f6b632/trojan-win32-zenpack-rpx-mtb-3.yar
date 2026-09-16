rule Trojan_Win32_Zenpack_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d a8 8b 4d ac 89 48 0c 89 58 04 8b 4d a8 89 08 c7 40 08 04 00 00 00 89 7d a4 89 55 a0 89 75 9c ff d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}