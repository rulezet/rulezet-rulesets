rule Trojan_Win32_Glupteba_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 03 89 c9 88 06 01 f9 81 c7 ?? ?? ?? ?? 46 81 e9 01 00 00 00 81 ef ?? ?? ?? ?? 81 c3 02 00 00 00 09 c9 29 f9 81 c1 7e 1a fc 72 39 d3 7e d1 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}