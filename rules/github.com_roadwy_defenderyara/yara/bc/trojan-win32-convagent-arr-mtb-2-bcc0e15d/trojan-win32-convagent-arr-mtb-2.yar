rule Trojan_Win32_Convagent_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f0 01 48 8b 4c 24 18 48 8b 5c 24 20 89 c2 48 8b 44 24 68 } 		$a_03_1 = {48 8b 72 18 48 83 c6 fe 48 83 fe 0b 0f 87 ?? ?? ?? ?? 4c 8b 42 ?? 48 8d 05 } 	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}