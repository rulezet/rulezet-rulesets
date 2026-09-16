rule Trojan_Win32_Cridex_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 14 8b c2 2b c3 81 c6 f0 25 08 01 83 e8 30 89 35 ?? ?? ?? ?? 89 31 8d 1c 45 09 00 00 00 39 7c 24 2c 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}