rule Trojan_Win32_Androm_BKL_MTB{
	meta:
		description = "Trojan:Win32/Androm.BKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {be a5 15 4f 0b 1c 09 30 65 89 7a f4 3c 91 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}