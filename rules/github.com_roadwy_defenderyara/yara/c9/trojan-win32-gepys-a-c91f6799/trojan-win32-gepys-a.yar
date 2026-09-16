rule Trojan_Win32_Gepys_A{
	meta:
		description = "Trojan:Win32/Gepys.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 40 11 49 8b 0d ?? ?? ?? ?? c6 41 12 6e 8b 15 ?? ?? ?? ?? c6 42 13 74 a1 } 		$a_03_1 = {2e 74 6d 70 00 47 45 54 [0-07] 50 4f 53 54 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}