rule Trojan_Win32_Fragtor_NFA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 3b cf 76 2e 6a e0 58 33 d2 f7 f1 3b 45 ?? 1b c0 40 75 1f e8 1c 9e ff ff c7 00 0c } 		$a_01_1 = {4d 00 4a 00 50 00 47 00 43 00 2e 00 54 00 4d 00 50 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}