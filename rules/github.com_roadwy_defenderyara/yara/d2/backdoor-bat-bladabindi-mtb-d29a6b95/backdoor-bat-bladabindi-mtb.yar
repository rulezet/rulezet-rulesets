rule Backdoor_BAT_Bladabindi_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {28 17 00 00 2b 7e ?? 00 00 0a 8e 20 f8 cb 00 00 58 20 91 85 01 00 20 df 49 ff ff 58 20 4c 25 00 00 7e 0b 00 00 04 0b 07 5f 65 20 b2 08 00 00 59 07 1f 1d 62 07 20 00 00 00 28 5a 58 } 		$a_02_1 = {28 03 00 00 06 18 16 8d 11 00 00 01 20 ?? ?? 00 00 20 ?? ?? 00 00 28 19 00 00 2b 14 20 f1 25 a8 55 20 35 20 58 aa d6 7e ?? 00 00 0a 8e 20 3b 4a 00 00 58 7e ?? 00 00 0a 8e 20 83 00 00 00 58 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}