rule Trojan_BAT_Taskun_AMMF_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 07 11 ?? 91 13 ?? 02 11 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 07 11 ?? 11 ?? 28 ?? 00 00 0a d2 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}