rule Trojan_Win32_Cridex_AR_MTB{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 08 79 03 01 a1 ?? ?? ?? ?? 89 13 83 c3 04 2b c1 83 6c 24 10 01 75 b3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}