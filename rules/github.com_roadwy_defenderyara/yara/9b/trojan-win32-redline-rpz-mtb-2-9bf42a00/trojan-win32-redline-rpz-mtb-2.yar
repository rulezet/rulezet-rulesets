rule Trojan_Win32_Redline_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 17 33 db 33 c3 33 d8 80 2f 80 8b f0 33 de 8b c6 80 07 34 33 d8 33 db 33 db f6 2f 47 e2 e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}