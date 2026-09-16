rule Trojan_Win64_Zusy_EH_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 eb 05 b9 58 20 99 00 48 29 cb 50 b8 86 15 1c 00 48 01 d8 83 38 00 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}