rule Trojan_Win32_Zenpack_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 8b 4d d4 8b 55 d8 be 00 01 00 00 81 c1 01 00 00 00 89 45 cc 89 c8 89 55 c8 99 f7 fe } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}