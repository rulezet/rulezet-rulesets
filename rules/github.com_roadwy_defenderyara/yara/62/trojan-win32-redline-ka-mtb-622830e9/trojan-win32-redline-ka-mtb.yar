rule Trojan_Win32_Redline_KA_MTB{
	meta:
		description = "Trojan:Win32/Redline.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 c7 33 45 c8 88 45 c7 0f b6 4d c7 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}