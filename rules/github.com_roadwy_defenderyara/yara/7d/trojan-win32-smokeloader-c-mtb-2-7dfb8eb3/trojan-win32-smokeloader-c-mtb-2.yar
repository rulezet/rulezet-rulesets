rule Trojan_Win32_SmokeLoader_C_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 ff 8b 45 08 0f be 04 10 69 c0 } 		$a_03_1 = {03 ce 8b 55 0c 03 55 ?? 88 0a 0f be 45 ?? 8b 4d 0c 03 4d ?? 0f b6 11 2b d0 8b 45 0c 03 45 ?? 88 10 eb } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}