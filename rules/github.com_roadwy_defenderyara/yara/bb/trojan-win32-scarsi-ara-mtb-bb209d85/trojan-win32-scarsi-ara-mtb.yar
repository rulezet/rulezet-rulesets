rule Trojan_Win32_Scarsi_ARA_MTB{
	meta:
		description = "Trojan:Win32/Scarsi.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f9 ff 74 29 8b 35 40 90 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 c4 73 40 00 30 14 0e 41 3b 0d 4c 90 40 00 72 c9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}