rule Trojan_BAT_Lokibot_RPR_MTB_2{
	meta:
		description = "Trojan:BAT/Lokibot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 25 2b 49 2b ec 2b 48 2b ee 2b 47 2b ef 2b 46 2b 47 2b 48 06 8e 69 5d 91 02 08 91 61 d2 ?? ?? ?? ?? ?? 08 17 58 0c 08 02 8e 69 32 e1 } 		$a_01_1 = {64 00 65 00 73 00 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00 61 00 6e 00 64 00 77 00 2e 00 74 00 6b 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}