rule Trojan_Win32_Neoreblamy_CL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c8 2b ca 03 4d e4 89 4d e4 } 		$a_01_1 = {ff ff 59 59 8b 4d } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}