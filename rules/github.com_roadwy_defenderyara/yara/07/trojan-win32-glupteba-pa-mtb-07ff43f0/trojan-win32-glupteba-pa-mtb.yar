rule Trojan_Win32_Glupteba_PA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b d6 c1 ea 05 03 54 24 28 8d 04 37 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}