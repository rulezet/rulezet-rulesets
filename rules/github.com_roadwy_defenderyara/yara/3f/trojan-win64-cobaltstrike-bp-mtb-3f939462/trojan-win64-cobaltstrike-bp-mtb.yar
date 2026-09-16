rule Trojan_Win64_CobaltStrike_BP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 27 25 34 34 29 23 2b 23 48 89 45 46 48 b8 2b 23 2f 35 2e 34 54 ae } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}