rule Trojan_Win32_Redline_GBS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 03 4d f4 8a 11 88 55 f3 0f be 45 f3 0f be 4d f3 8b 55 f4 83 e2 2f 8b 75 08 0f be 14 16 33 ca 03 c1 8b 4d 0c 03 4d f4 88 01 0f be 55 f3 8b 45 0c 03 45 f4 0f b6 08 2b ca 8b 55 0c 03 55 f4 88 0a } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}