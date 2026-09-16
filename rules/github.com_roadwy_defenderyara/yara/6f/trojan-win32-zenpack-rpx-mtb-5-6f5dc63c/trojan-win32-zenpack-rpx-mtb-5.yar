rule Trojan_Win32_Zenpack_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8d 9b 00 00 00 00 83 3d ?? ?? ?? 00 0b 75 0e 8d 8c 24 2c 01 00 00 51 6a 00 6a 00 ff d7 81 fe 4c 13 00 00 0f 85 19 0b 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}