rule Trojan_BAT_Taskun_ARAT_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 13 05 11 04 17 58 11 04 20 00 56 01 00 5d 13 06 20 00 56 01 00 5d 13 07 07 11 06 91 13 08 07 11 06 11 08 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 11 04 1f 16 5d 91 61 07 11 07 91 11 05 58 11 05 5d 59 d2 9c 11 04 17 58 13 04 11 04 20 00 56 01 00 32 a3 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}