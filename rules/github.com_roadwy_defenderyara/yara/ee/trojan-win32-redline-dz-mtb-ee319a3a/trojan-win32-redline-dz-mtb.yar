rule Trojan_Win32_Redline_DZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 d3 0f b6 4d d3 2b 4d d4 88 4d d3 0f b6 55 d3 f7 da 88 55 d3 0f b6 45 d3 c1 f8 03 0f b6 4d d3 c1 e1 05 0b c1 88 45 d3 8b 55 d4 8a 45 d3 88 44 15 e0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}