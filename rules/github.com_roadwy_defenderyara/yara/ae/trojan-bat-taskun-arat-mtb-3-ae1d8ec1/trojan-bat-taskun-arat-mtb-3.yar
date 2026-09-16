rule Trojan_BAT_Taskun_ARAT_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 00 01 00 00 13 06 11 05 17 58 13 07 11 05 20 00 1e 01 00 5d 13 08 11 07 20 00 1e 01 00 5d 13 09 06 11 08 91 13 0a 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 05 1f 16 5d 91 13 0b 06 11 09 91 11 06 58 13 0c 06 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 11 05 20 00 1e 01 00 fe 04 13 0d 11 0d 2d 8f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}