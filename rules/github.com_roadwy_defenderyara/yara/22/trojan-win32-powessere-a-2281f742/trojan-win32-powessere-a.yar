rule Trojan_Win32_Powessere_A{
	meta:
		description = "Trojan:Win32/Powessere.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 } 		$a_03_1 = {56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 c6 45 } 		$a_01_2 = {8a 04 07 32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}