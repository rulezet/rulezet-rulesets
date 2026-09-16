rule Trojan_Win32_Redline_GMJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 2b f7 f7 e9 c1 ee de 66 c1 d8 35 66 f7 e8 81 f7 ed 02 00 00 66 c1 df 44 8b 75 c4 8b 4d dc 8b 55 d8 8b 46 24 8d 04 48 0f b7 0c 10 8b 46 1c 8d 04 88 8b 4d f8 8b 04 10 89 45 d4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}