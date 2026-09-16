rule Trojan_Win32_Zusy_PGY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f2 55 48 83 c0 01 88 50 ff 0f b6 10 84 d2 75 ef } 		$a_01_1 = {83 f1 55 48 83 c2 01 88 4a ff 0f b6 0a 84 c9 75 ef } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}