rule Trojan_BAT_Taskun_AMMH_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 [0-32] 1f 16 5d 91 61 07 11 ?? 91 59 20 00 01 00 00 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}