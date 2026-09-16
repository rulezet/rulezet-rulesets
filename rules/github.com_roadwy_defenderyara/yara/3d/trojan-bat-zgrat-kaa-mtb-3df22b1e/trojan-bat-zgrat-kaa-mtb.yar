rule Trojan_BAT_ZgRAT_KAA_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee } 		$a_01_1 = {4b 66 65 69 6f 66 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}