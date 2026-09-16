rule Trojan_Win32_Fareit_R_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.R!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 8b f0 8b ca 85 c9 72 10 41 33 d2 8d 3c 32 8a 07 34 e5 88 07 42 49 75 f3 5f 5e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}