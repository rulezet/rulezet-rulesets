rule Trojan_Win32_Fareit_RB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 57 8d 3d ?? ?? ?? ?? 8b 75 08 ac 34 37 aa 3c 00 75 f8 5f 5e c9 c2 04 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}