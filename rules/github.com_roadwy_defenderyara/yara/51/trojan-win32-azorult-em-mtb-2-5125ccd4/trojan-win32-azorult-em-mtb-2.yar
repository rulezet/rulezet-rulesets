rule Trojan_Win32_Azorult_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 7c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18 8b 44 24 24 29 44 24 14 ff 4c 24 1c } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}