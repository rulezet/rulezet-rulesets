rule Trojan_Win32_Emotet_DK{
	meta:
		description = "Trojan:Win32/Emotet.DK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f 37 68 53 42 4d 65 51 65 49 66 6d 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}