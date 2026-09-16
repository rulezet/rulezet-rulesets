rule Trojan_Win32_Zusy_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 81 80 80 80 f7 e1 c1 ea 07 02 d1 30 91 ?? ?? ?? ?? 41 81 f9 eb d5 06 00 72 e5 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}