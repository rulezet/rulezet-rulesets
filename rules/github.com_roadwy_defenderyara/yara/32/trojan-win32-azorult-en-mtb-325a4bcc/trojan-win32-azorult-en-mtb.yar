rule Trojan_Win32_Azorult_EN_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 01 08 c3 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}