rule Trojan_Win32_Androm_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 85 c0 f3 a4 75 0b 5f 5e 5d 5b 81 c4 04 06 00 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}