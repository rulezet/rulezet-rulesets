rule Trojan_Win32_Rolnoxo_A{
	meta:
		description = "Trojan:Win32/Rolnoxo.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e9 ca 00 00 00 8d bd 64 fd ff ff 4f 8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 a5 66 a5 33 c0 8d 7d cc ab ab 6a 11 ab } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}