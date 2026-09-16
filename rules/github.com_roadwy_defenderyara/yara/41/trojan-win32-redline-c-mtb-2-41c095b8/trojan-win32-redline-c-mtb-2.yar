rule Trojan_Win32_RedLine_C_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 03 54 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d7 31 54 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}