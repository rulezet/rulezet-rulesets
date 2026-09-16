rule Trojan_BAT_Disabler_EM_MTB_2{
	meta:
		description = "Trojan:BAT/Disabler.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 01 00 00 00 62 61 fe 0e 11 00 fe 0c 11 00 fe 0c 13 00 58 fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 06 00 00 00 62 61 fe 0e 11 00 fe 0c 11 00 fe 0c 14 00 58 fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 0b 00 00 00 64 61 fe 0e 11 00 fe 0c 11 00 fe 0c 15 00 58 fe 0e 11 00 fe 0c 13 00 20 0c 00 00 00 62 fe 0c 13 00 59 fe 0c 14 00 61 fe 0c 11 00 59 fe 0e 11 00 fe 0c 11 00 76 6c 6d 58 13 04 11 08 07 17 59 40 50 00 00 00 06 16 3e 49 00 00 00 11 04 11 06 61 } 		$a_01_1 = {6f 66 66 44 65 66 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}