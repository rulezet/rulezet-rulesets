rule Trojan_Win32_Glupteba_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 31 19 41 89 f2 39 c1 75 e8 c3 81 c2 ?? ?? ?? ?? 46 8d 1c 3b 8b 1b 81 e3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}