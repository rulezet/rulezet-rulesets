rule Trojan_Win32_Zusy_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0f 8a c1 32 c4 8a e1 88 07 47 43 3b de 72 f0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}