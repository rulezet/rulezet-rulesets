rule Trojan_Win32_Glupteba_RPD_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d 08 8b 55 fc f7 da 8b 45 08 8b 08 2b ca 8b 55 08 89 0a 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}