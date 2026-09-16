rule Trojan_Win32_Phorpiex_APX_MTB_2{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 8d 45 e8 50 ff 75 f8 8d 85 d0 e9 ff ff 50 ff 75 f0 ff 15 ?? ?? ?? ?? 8d 45 f8 50 68 ff 0f 00 00 8d 85 d0 e9 ff ff 50 ff 75 f4 } 		$a_01_1 = {31 00 37 00 38 00 2e 00 31 00 36 00 2e 00 35 00 34 00 2e 00 31 00 30 00 39 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}