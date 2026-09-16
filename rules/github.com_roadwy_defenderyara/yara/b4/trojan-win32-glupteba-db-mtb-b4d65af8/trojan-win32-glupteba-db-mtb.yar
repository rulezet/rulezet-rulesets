rule Trojan_Win32_Glupteba_DB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 c4 10 08 00 00 90 09 06 00 8b 15 } 		$a_03_1 = {89 04 24 b8 d1 05 00 00 01 04 24 8b 0c 24 8a 14 31 a1 ?? ?? ?? ?? 88 14 30 81 c4 10 0c 00 00 90 09 05 00 a1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}