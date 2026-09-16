rule Trojan_Win32_Redline_GPAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c 65 34 22 2c 73 34 2a 88 86 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}