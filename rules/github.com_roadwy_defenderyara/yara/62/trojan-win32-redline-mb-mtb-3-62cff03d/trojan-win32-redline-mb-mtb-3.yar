rule Trojan_Win32_Redline_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 5c 24 10 89 74 24 24 8b 44 24 2c 01 44 24 24 8b 44 24 18 90 01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}