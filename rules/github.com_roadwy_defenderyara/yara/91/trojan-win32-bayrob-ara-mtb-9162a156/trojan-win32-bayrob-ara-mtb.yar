rule Trojan_Win32_Bayrob_ARA_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 30 11 41 40 3b cf 75 f6 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}