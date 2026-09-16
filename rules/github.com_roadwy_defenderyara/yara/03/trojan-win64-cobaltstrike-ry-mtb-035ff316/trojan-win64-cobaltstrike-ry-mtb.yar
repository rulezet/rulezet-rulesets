rule Trojan_Win64_CobaltStrike_RY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 08 41 30 14 08 48 8d 51 01 48 89 d1 49 39 d1 75 ed } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}