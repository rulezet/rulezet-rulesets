rule Trojan_Win32_Redline_MF_MTB{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f c2 fe 07 47 e2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}