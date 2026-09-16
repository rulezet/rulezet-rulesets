rule Trojan_Win32_Androm_BAP_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ef 66 18 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}