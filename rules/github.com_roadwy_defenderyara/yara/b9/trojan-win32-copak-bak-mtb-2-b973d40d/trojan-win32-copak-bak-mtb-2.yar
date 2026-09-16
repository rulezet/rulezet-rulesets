rule Trojan_Win32_Copak_BAK_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 ff 53 21 ff 01 d2 89 d7 8b 34 24 83 c4 04 29 d7 21 d2 41 09 ff 81 ef a8 48 13 b1 42 81 f9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}