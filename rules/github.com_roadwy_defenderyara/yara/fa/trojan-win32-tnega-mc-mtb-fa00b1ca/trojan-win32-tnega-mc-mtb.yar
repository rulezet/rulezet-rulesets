rule Trojan_Win32_Tnega_MC_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 03 43 81 c2 3a 82 84 37 81 c7 de 6b ea e2 39 f3 75 ?? 09 d2 09 d2 c3 90 0a 26 00 b8 ?? ?? ?? ?? 47 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}