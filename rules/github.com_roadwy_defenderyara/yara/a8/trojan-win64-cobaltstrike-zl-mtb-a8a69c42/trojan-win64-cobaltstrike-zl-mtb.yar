rule Trojan_Win64_CobaltStrike_ZL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 30 06 48 ff c6 48 ff c3 48 ff c9 80 fb 28 75 03 48 33 db 83 f9 00 7f } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}