rule Trojan_Win64_CobaltStrike_HR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 2c 60 88 5c 3c 60 44 88 44 2c 60 0f b6 6c 3c 60 44 01 c5 40 0f b6 ed 0f b6 5c 2c 60 41 30 1c 07 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}