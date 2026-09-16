rule Trojan_BAT_Taskun_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 11 0f 11 0e 11 0f 8e 69 6a 5d d4 91 61 } 		$a_03_1 = {5d d4 91 61 28 ?? 00 00 0a 07 06 17 6a 58 11 05 6a 5d d4 91 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}