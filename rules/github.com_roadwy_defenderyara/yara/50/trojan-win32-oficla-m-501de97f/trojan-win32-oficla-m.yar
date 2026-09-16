rule Trojan_Win32_Oficla_M{
	meta:
		description = "Trojan:Win32/Oficla.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f6 78 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 90 1b 00 8d 45 f3 89 44 24 04 } 		$a_01_1 = {30 0c 02 40 83 f8 10 75 f1 83 c2 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}