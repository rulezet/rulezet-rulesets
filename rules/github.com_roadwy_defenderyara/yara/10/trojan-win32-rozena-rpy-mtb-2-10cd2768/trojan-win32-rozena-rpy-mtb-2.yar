rule Trojan_Win32_Rozena_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Rozena.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 c7 44 24 38 5c 00 00 00 f7 f1 c7 44 24 34 74 00 00 00 c7 44 24 30 6f 00 00 00 c7 44 24 2c 6c 00 00 00 c7 44 24 28 73 00 00 00 c7 44 24 24 6c 00 00 00 c7 44 24 20 69 00 00 00 c7 44 24 1c 61 00 00 00 c7 44 24 18 6d 00 00 00 c7 44 24 14 5c 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}