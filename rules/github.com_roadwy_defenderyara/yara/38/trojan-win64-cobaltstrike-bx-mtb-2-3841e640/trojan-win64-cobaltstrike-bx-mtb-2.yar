rule Trojan_Win64_CobaltStrike_BX_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 48 8b 55 e0 8b 45 fc 48 98 0f b6 04 02 31 c8 88 45 df 8b 45 fc 48 63 d0 48 8b 45 20 48 01 c2 0f b6 45 df 88 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}