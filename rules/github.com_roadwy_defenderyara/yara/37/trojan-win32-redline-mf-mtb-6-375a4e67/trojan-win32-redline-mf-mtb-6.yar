rule Trojan_Win32_Redline_MF_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a } 		$a_01_1 = {8a 45 cc 88 45 cb 0f b6 4d cf 8b 55 08 03 55 d0 0f b6 02 03 c1 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 8a 02 2c 01 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 0f b6 02 83 e8 02 8b 4d 08 03 4d d0 88 01 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}