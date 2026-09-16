rule Trojan_Win32_Zusy_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 8b 47 28 0f b6 04 10 30 04 0b 83 c1 01 39 cd 75 e9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}