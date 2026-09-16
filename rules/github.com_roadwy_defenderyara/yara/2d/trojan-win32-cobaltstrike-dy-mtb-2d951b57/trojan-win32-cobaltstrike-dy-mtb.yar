rule Trojan_Win32_CobaltStrike_DY_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 75 f8 8a 44 15 ?? 30 44 0b 04 41 3b ce 72 ec } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}