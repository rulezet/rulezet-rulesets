rule Trojan_Win64_CobaltStrike_CCHZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 60 48 8d 05 a4 86 00 00 48 89 45 f0 48 8d 05 a8 86 00 00 48 89 45 d0 48 8d 05 a8 86 00 00 48 89 45 d8 48 8d 05 a8 86 00 00 48 89 45 c0 48 8d 05 b7 86 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}