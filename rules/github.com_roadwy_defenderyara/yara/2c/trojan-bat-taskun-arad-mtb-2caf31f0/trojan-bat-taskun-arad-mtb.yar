rule Trojan_BAT_Taskun_ARAD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 2d 07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9 08 17 58 0c 11 04 17 58 13 04 11 04 07 6f 2d 00 00 0a 32 b0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}