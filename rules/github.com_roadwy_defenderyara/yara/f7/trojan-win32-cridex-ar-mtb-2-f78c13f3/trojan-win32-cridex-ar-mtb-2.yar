rule Trojan_Win32_Cridex_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 20 69 d2 34 50 01 00 05 40 26 00 01 89 44 24 20 89 01 8b 4c 24 18 a3 ?? ?? ?? ?? 03 d6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}