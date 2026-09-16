rule Trojan_Win32_Redline_GJX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f a4 80 2f 67 47 e2 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}