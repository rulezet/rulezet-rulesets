rule Trojan_Win32_Zenpak_RB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 20 29 c2 4a e8 21 00 00 00 c3 31 c2 01 c2 42 31 1d ?? ?? ?? ?? b8 06 00 00 00 8d 05 ?? ?? ?? ?? 01 30 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}