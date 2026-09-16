rule Trojan_Win32_Zenpack_EC_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 20 83 f2 07 42 01 d0 eb 30 83 f0 04 42 } 		$a_03_1 = {31 18 83 e8 04 01 d0 8d 05 ?? ?? ?? ?? 31 30 e9 ab fa ff ff c3 } 	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}