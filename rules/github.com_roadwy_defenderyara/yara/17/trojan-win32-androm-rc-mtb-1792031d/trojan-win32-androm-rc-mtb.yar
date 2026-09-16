rule Trojan_Win32_Androm_RC_MTB{
	meta:
		description = "Trojan:Win32/Androm.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 54 24 08 52 6a 40 68 78 da 04 00 56 ff d0 6a 00 6a 00 56 56 6a 00 6a 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}