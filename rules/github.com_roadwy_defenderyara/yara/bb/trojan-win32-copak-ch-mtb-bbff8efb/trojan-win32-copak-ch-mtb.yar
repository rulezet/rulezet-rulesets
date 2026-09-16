rule Trojan_Win32_Copak_CH_MTB{
	meta:
		description = "Trojan:Win32/Copak.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 21 d2 31 0b 81 c6 ?? ?? ?? ?? 4a 81 ee } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}