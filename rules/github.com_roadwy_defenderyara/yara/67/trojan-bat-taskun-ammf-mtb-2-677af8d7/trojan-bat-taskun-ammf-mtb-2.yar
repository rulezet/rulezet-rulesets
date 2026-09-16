rule Trojan_BAT_Taskun_AMMF_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 91 20 ff 00 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}