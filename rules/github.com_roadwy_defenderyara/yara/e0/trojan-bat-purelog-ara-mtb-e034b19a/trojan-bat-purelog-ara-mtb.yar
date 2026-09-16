rule Trojan_BAT_PureLog_ARA_MTB{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 58 0c 06 07 08 07 8e 69 08 59 6f ?? ?? ?? 0a 25 0d 16 30 ea } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}