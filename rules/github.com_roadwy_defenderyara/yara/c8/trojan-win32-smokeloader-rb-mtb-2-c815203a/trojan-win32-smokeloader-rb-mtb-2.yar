rule Trojan_Win32_SmokeLoader_RB_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 67 88 2a c7 84 24 ?? ?? ?? ?? 60 c3 73 76 c7 84 24 ?? ?? ?? ?? 41 59 8d 4d c7 84 24 ?? ?? ?? ?? 9f f8 ff 08 c7 84 24 ?? ?? ?? ?? 5f 05 09 1a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}