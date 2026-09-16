rule Trojan_Win32_Farfli_ASDE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8a 1c 08 80 c3 ?? 88 1c 08 8b 4d ec 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 7c } 		$a_01_1 = {c6 44 24 18 43 c6 44 24 19 72 c6 44 24 1b 61 88 4c 24 1c c6 44 24 1e 45 c6 44 24 1f 76 c6 44 24 21 6e 88 4c 24 22 c6 44 24 23 41 88 5c 24 24 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}