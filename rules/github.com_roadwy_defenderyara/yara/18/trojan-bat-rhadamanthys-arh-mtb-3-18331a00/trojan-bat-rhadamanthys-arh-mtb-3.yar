rule Trojan_BAT_Rhadamanthys_ARH_MTB_3{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 10 1f 0c 58 28 ?? 00 00 06 13 13 02 11 10 1f 10 58 28 ?? 00 00 06 13 14 02 11 10 1f 14 58 28 ?? 00 00 06 13 15 11 14 16 31 3e 11 14 8d 14 00 00 01 13 16 02 11 15 11 16 16 11 16 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 06 7b 0b 00 00 04 11 0f 11 13 58 11 16 11 16 8e 69 12 04 } 		$a_01_1 = {31 00 34 00 37 00 2e 00 34 00 35 00 2e 00 34 00 34 00 2e 00 34 00 32 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}