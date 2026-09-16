rule Trojan_Win32_CobaltStrike_PA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 83 ec ?? 39 da 7d ?? 89 d1 8b 75 10 83 e1 03 8a 0c 0e 8b 75 08 32 0c 16 88 0c 10 42 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}