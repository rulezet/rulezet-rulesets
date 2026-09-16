rule Trojan_Win32_Redline_MP_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0a 34 73 2c 6c 34 74 04 4e 34 70 2c 65 34 22 2c 73 34 2a 88 04 0a 41 3b 4c 24 08 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}