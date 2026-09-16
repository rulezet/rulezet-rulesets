rule Trojan_Win32_Androm_BAQ_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ef 31 d4 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 0f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}