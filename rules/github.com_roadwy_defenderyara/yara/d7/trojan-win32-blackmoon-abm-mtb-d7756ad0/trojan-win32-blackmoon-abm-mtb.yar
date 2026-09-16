rule Trojan_Win32_BlackMoon_ABM_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 07 47 08 c0 74 dc 89 f9 79 07 0f b7 07 47 50 47 b9 57 48 f2 ae 55 ff 96 3c 64 2d 00 09 c0 74 07 89 03 83 c3 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}