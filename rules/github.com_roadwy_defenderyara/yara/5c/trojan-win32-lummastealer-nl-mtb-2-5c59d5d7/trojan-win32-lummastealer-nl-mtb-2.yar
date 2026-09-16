rule Trojan_Win32_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 02 8b e9 33 c0 33 ff 3b eb 74 2e } 		$a_03_1 = {e8 36 fa ff ff 83 c4 ?? 80 7e 48 00 75 10 85 c0 78 0c 8b 4c 24 14 88 } 	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}