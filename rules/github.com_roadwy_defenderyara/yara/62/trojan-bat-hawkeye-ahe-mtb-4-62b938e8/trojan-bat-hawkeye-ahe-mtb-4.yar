rule Trojan_BAT_Hawkeye_AHE_MTB_4{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 25 17 58 0c 12 00 28 ?? 00 00 0a 9c 07 08 25 17 58 0c 12 00 28 ?? 00 00 0a 9c 07 08 25 17 58 0c 12 00 28 } 		$a_01_1 = {16 0b 2b 10 06 07 02 02 8e 69 17 59 07 59 91 9c 07 17 58 0b 07 06 8e 69 fe 04 0d 09 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}