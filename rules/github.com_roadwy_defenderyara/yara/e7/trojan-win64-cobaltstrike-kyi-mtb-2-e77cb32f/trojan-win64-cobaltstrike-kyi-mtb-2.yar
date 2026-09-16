rule Trojan_Win64_CobaltStrike_KYI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 07 28 00 2a 00 48 8d 05 c3 1b 00 00 c7 45 c7 30 00 00 00 48 89 45 0f 4c 8d 45 c7 48 8d 45 07 48 89 5d cf 0f 57 c0 48 89 45 d7 8d 53 0d c7 45 df 40 00 00 00 48 8d 4d bf f3 0f 7f 45 e7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}