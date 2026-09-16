rule Trojan_Win64_BumbleBee_DD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c2 44 8b cf 48 8b 93 38 01 00 00 48 33 d0 48 63 c7 48 23 93 e8 02 00 00 48 3b c2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}