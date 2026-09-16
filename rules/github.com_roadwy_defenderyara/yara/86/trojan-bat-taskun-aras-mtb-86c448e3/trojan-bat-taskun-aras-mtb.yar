rule Trojan_BAT_Taskun_ARAS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 04 5d 13 09 07 11 09 91 08 11 05 1f 16 5d 91 61 13 0a 11 0a 07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58 13 0b 07 11 09 11 0b 20 00 01 00 00 5d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0c 11 0c 2d b2 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}