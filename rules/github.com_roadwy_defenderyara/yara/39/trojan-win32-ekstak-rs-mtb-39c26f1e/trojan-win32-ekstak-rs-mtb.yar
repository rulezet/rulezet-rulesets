rule Trojan_Win32_Ekstak_RS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 e8 0a 74 fb ff 8b f0 e9 } 		$a_01_1 = {40 00 00 40 5f 72 65 61 63 74 5f } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}