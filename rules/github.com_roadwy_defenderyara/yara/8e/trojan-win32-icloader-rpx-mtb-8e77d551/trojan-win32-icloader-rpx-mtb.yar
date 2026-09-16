rule Trojan_Win32_ICLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 33 ff 57 ff d6 83 f8 07 75 1f 6a 01 ff d6 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 08 5f b8 01 00 00 00 5e c3 8b c7 5f 5e c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}