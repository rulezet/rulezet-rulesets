rule Trojan_Win32_Nedsym_G_2{
	meta:
		description = "Trojan:Win32/Nedsym.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ac 84 c0 74 13 fe c2 8a ca 80 e1 1f 80 c1 61 fe ce 32 ce 32 c1 aa eb e8 } 		$a_01_1 = {4e 80 3e 77 75 0d 80 7e 01 77 75 07 80 7e 02 77 75 01 ad } 		$a_03_2 = {81 3e 52 4d 5f 51 0f 85 ?? ?? ?? ?? 81 7e 04 50 5f 45 4e 0f 85 ?? ?? ?? ?? 81 7e 08 43 4f 44 45 0f 85 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}