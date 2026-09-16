rule Trojan_Win32_Zusy_GTM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 65 95 ef 60 b4 5a 30 28 ed 61 51 ea } 		$a_80_1 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}