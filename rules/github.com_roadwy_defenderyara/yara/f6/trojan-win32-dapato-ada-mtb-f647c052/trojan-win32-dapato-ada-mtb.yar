rule Trojan_Win32_Dapato_ADA_MTB{
	meta:
		description = "Trojan:Win32/Dapato.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 03 55 c8 03 c2 8b 55 e4 03 d6 8b cf e8 ?? ?? ?? ?? 01 7d c8 6a 00 e8 ?? ?? ?? ?? 03 c7 01 c6 8b 45 d0 01 c6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}