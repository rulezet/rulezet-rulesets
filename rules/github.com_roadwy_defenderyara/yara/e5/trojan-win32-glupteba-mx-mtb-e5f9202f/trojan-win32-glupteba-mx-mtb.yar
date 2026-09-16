rule Trojan_Win32_Glupteba_MX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 03 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 44 24 ?? 8b 44 24 ?? 85 c0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}