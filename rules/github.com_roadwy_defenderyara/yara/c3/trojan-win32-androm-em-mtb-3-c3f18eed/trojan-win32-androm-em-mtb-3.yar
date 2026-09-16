rule Trojan_Win32_Androm_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f8 8b d1 81 c6 90 da 04 00 8b df c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 5f 5e 85 db 5b 75 03 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}