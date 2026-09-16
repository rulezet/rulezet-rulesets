rule Trojan_Win32_Emotet_AB{
	meta:
		description = "Trojan:Win32/Emotet.AB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 81 e9 fc a1 29 00 09 c8 83 e8 20 8d 15 78 97 40 00 89 1a 8d 0d b0 be 5c 00 89 fa } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}