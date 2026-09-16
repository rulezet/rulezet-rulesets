rule Trojan_Win32_Androm_BAE_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 16 0f b6 44 10 ff 33 07 5a 88 02 ff 06 4b 75 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}