rule Trojan_Win32_Azorult_EM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 8b 7c 24 18 8b ce c1 e9 05 03 cd 03 fe } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}