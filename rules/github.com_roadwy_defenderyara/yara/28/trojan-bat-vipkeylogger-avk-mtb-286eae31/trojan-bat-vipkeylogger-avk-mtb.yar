rule Trojan_BAT_Vipkeylogger_AVK_MTB{
	meta:
		description = "Trojan:BAT/Vipkeylogger.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 91 58 11 09 20 ff 00 00 00 5f 58 20 ff 00 00 00 5f 0b 11 1c 20 ?? 01 00 00 91 1f 7f 59 13 1a } 		$a_01_1 = {11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f 11 1c 1f 21 91 1f 09 5b 13 1a } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}