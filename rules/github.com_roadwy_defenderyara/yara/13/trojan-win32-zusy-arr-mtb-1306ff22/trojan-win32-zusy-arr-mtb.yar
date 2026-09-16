rule Trojan_Win32_Zusy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_81_0 = {41 21 6c 40 6c 24 43 21 6c 5e 69 23 63 25 6b } 	condition:
		((#a_81_0  & 1)*20) >=20
 
}