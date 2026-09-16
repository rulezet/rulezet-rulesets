rule Trojan_Win32_Dridex_AR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 05 fc 55 0e 01 89 02 8b 15 ?? ?? ?? ?? 89 44 24 1c a3 ?? ?? ?? ?? 8b c7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}