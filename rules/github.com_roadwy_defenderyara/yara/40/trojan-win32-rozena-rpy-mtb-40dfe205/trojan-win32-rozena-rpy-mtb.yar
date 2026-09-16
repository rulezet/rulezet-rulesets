rule Trojan_Win32_Rozena_RPY_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 56 90 e9 } 		$a_01_1 = {90 ff d5 89 c3 89 c7 e9 } 		$a_01_2 = {ff d0 90 3c 06 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}