rule Trojan_Win32_Deyma_MBJZ_MTB{
	meta:
		description = "Trojan:Win32/Deyma.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 33 db 33 d8 80 07 ?? 33 c6 8b f3 8b c6 8b c0 8b f3 8b db 33 d8 33 c3 33 c6 f6 2f 47 e2 ab } 		$a_01_1 = {76 64 77 78 66 79 74 68 64 72 6e 72 61 6d 64 70 65 76 77 63 78 71 74 64 67 6c 6b 74 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}