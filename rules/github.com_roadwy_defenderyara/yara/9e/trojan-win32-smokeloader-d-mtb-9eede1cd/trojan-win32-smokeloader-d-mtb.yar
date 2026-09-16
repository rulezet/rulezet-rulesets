rule Trojan_Win32_SmokeLoader_D_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 ff 8b 45 08 0f be 14 10 69 d2 } 		$a_03_1 = {03 ce 8b 45 0c 03 45 ?? 88 08 0f be 4d ?? 8b 55 0c 03 55 ?? 0f b6 02 2b c1 8b 4d 0c 03 4d ?? 88 01 eb } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}