rule Trojan_Win32_Zenpack_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 5e a8 66 32 f7 64 24 1c 8b 44 24 1c 81 6c 24 0c 00 02 32 55 81 44 24 34 9f 12 a5 12 b8 bf 91 2a 1d f7 64 24 10 8b 44 24 10 81 6c 24 3c fa 7a 76 1f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}