rule Trojan_Win32_Redline_RG_MTB{
	meta:
		description = "Trojan:Win32/Redline.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 3c 8d 5c 24 2c 8b f7 81 f6 6c 03 00 00 83 7c 24 40 10 0f 43 5c 24 2c 53 c1 ef 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}