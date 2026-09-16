rule Trojan_Win32_Emotet_BE{
	meta:
		description = "Trojan:Win32/Emotet.BE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 6c 5c 69 4d 53 2d 73 72 76 72 65 67 35 36 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}