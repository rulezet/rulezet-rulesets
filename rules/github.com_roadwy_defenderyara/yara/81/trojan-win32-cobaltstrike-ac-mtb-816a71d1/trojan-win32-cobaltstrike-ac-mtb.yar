rule Trojan_Win32_CobaltStrike_AC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 83 f8 0e 0f 45 c8 8a 81 8c 62 08 10 30 04 32 42 8d 41 01 3b d7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}