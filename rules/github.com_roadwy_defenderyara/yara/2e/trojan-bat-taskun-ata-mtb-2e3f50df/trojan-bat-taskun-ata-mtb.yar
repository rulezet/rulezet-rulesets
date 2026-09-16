rule Trojan_BAT_Taskun_ATA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 00 02 04 06 6f ?? 00 00 0a 0b 05 03 6f ?? 00 00 0a 59 0c 03 07 08 28 ?? 00 00 06 00 00 06 17 58 0a } 		$a_03_1 = {1e 62 60 0f 01 28 ?? 00 00 0a 60 13 06 02 19 8d ?? 00 00 01 25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c 6f } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}