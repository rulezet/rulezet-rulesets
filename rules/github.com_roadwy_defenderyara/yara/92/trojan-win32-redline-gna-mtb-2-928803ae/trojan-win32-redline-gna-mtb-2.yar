rule Trojan_Win32_Redline_GNA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 80 07 ?? 8b c3 33 c3 33 c0 33 c3 33 d8 8b de 33 c3 33 f6 8b f6 f6 2f 47 e2 } 		$a_03_1 = {8b c3 33 de 80 07 ?? 8b c6 33 c0 8b db 8b c6 8b d8 33 c3 33 f6 33 de 33 c3 f6 2f 47 e2 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}