rule Trojan_Win32_Redline_MO_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 f7 75 14 8b 45 f0 c1 ea 02 0f be 04 10 6b c0 2b c1 e0 06 b9 2c 00 00 00 99 f7 f9 b9 17 00 00 00 99 f7 f9 6b f0 0b 8b 45 0c 8b 4d f4 0f be 14 08 31 f2 88 14 08 8b 45 f4 83 c0 01 89 45 f4 e9 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}