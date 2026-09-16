rule Trojan_Win32_Zusy_AZY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 81 a8 7c 42 00 30 04 0a 83 e9 01 } 		$a_01_1 = {8a 8d c1 42 ff ff 32 8d c0 42 ff ff 80 c9 50 30 c1 88 8c 15 c0 42 ff ff 42 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}