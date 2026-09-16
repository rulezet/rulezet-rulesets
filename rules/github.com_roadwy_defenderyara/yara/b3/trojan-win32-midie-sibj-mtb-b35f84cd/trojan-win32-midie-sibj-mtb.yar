rule Trojan_Win32_Midie_SIBJ_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {79 7a 6c 68 62 78 78 68 2e 64 6c 6c } 		$a_03_1 = {33 c9 85 db 74 ?? 8a 04 39 [0-20] 34 a2 [0-20] fe c0 34 4f [0-20] 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}