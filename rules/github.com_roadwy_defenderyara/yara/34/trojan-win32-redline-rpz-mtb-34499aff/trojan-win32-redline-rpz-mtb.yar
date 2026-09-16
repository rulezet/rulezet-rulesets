rule Trojan_Win32_Redline_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 17 33 f6 8b f0 8b d8 33 de } 		$a_01_1 = {33 c3 33 c3 33 c3 8b d8 33 f0 33 f0 f6 2f 47 e2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}