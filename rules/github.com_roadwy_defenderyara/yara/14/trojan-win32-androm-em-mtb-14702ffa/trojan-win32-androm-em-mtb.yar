rule Trojan_Win32_Androm_EM_MTB{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 98 30 80 40 00 32 d9 88 98 30 80 40 00 40 83 f8 08 7c ec } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}