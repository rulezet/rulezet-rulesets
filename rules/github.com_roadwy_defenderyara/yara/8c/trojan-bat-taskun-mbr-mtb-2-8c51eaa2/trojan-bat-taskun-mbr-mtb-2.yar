rule Trojan_BAT_Taskun_MBR_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.MBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 04 07 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 04 09 11 04 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 05 06 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 08 17 58 0c 08 03 6f 7c 00 00 0a 32 b6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}