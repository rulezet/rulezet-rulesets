rule Trojan_BAT_Taskun_MBR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 1f 18 62 0a 06 7e ?? 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e ?? 00 00 04 02 18 58 91 1e 62 60 0a 06 } 		$a_03_1 = {65 6e 63 72 79 70 74 6f [0-09] 65 78 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}