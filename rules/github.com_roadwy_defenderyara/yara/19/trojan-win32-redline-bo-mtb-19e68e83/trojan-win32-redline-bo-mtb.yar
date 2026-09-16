rule Trojan_Win32_Redline_BO_MTB{
	meta:
		description = "Trojan:Win32/Redline.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b c7 c1 e8 05 c7 05 [0-04] 19 36 6b ff 89 45 0c 8b 45 e4 01 45 0c 83 65 08 00 8b c7 c1 e0 04 03 45 f0 8d 0c 3e 33 c1 33 45 0c 2b d8 8b 45 e8 01 45 08 2b 75 08 ff 4d fc 0f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}