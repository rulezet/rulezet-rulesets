rule Trojan_Win32_Glupteba_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 03 d5 03 c6 31 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 2c 29 44 24 18 4b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}