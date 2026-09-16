rule Trojan_Win32_Fragtor_KAE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0b 81 c0 ?? ?? ?? ?? 29 d7 81 e1 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? f7 d2 31 0e f7 d2 29 fa 46 47 4f 43 29 c2 89 c7 81 fe } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}