rule Trojan_Win32_Emotet_BU{
	meta:
		description = "Trojan:Win32/Emotet.BU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 65 68 41 68 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}