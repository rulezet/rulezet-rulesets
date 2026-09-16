rule Trojan_BAT_Taskun_ARAT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 5d 13 08 07 11 08 91 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 11 04 1f 16 5d 91 61 13 09 11 09 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 13 0a 07 11 08 11 0a 20 00 01 00 00 5d d2 9c 11 04 17 58 13 04 11 04 09 08 17 58 5a 32 af } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}