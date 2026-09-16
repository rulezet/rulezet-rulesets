rule Trojan_Win32_CobaltStrike_BN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 33 8a 04 17 8d 4b ?? 83 e1 07 43 d2 c8 88 02 3b 5d fc 7c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}