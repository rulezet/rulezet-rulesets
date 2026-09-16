rule Trojan_BAT_Taskun_AMBE_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 ?? 61 13 ?? 07 11 ?? 07 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}