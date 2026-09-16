rule Trojan_Win32_Small_EC_MTB{
	meta:
		description = "Trojan:Win32/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 00 00 00 00 50 b8 00 00 00 00 50 b8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 b8 00 00 00 00 50 e8 } 		$a_01_1 = {39 c1 0f 84 2e 00 00 00 8b 45 fc 89 c1 40 89 45 fc c1 e1 02 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}