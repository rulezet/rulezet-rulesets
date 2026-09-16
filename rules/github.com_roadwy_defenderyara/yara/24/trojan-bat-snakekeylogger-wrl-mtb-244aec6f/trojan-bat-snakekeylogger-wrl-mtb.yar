rule Trojan_BAT_Snakekeylogger_WRL_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.WRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 25 17 59 } 		$a_03_1 = {fe 02 0c 08 2d df 28 ?? ?? ?? 06 00 16 2d e8 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}