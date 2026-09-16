rule Trojan_Win32_Graftor_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Graftor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 10 8a 14 1a 8b 4d 10 30 14 31 ff 00 39 38 75 03 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}