rule Trojan_Win32_Glupteba_MB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 ca 89 44 24 1c 89 4c 24 14 89 35 c4 94 b9 00 8b 44 24 1c 01 05 c4 94 b9 00 a1 c4 94 b9 00 89 44 24 30 89 74 24 1c 8b 44 24 30 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}