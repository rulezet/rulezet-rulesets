rule Trojan_Win32_Upatre_AUP_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 8a 06 46 8a 0f 32 c1 88 07 47 59 4b 74 07 49 75 ee 5b 5b 5f c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}