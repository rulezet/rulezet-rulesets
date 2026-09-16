rule Trojan_Win32_Redline_RPZ_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c4 89 44 24 2c 8b 41 3c 53 8b da 89 4c 24 0c 55 8b 54 08 78 33 ed 8b 44 0a 20 03 d1 89 54 24 18 03 c1 56 57 8b 52 18 89 5c 24 14 89 44 24 10 89 54 24 1c 85 d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}