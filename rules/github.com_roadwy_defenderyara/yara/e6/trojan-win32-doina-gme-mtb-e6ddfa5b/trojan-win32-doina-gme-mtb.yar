rule Trojan_Win32_Doina_GME_MTB{
	meta:
		description = "Trojan:Win32/Doina.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 56 18 8a 44 82 ff f7 ff 8a fc 8d 14 8a 3c 80 73 ?? 02 c0 eb ?? 34 1b 41 88 02 3b 0e } 		$a_03_1 = {57 8b f8 b8 ?? ?? ?? ?? 48 46 08 9a c7 06 0a bf } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}