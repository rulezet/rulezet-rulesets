rule Trojan_Win32_Zusy_SXL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 e3 8b 45 a0 8d 4c 10 eb 8b 55 9c 2b 95 d8 fe ff ff 23 ca 88 8d 77 ff ff ff 8b 85 00 ff ff ff 2b 45 b8 8b 4d 9c 2b 4d f4 23 4d 9c } 		$a_03_1 = {0f b7 45 ac 03 d0 2b 55 cc 83 ea ?? 0f b6 8d 5f ff ff ff 23 ca 88 8d 5f ff ff ff } 	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}