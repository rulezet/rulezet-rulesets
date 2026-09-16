rule Trojan_Win32_Amadey_AMD_MTB_4{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ff 10 88 9b e0 80 46 00 8b c3 b9 2c 63 46 00 0f 43 0d 2c 63 46 00 99 f7 fe 8a 04 0a 88 83 f0 81 46 00 43 81 fb } 		$a_03_1 = {83 7d 4c 10 8d 45 38 ff 75 48 0f 43 45 38 b9 c0 ?? 46 00 50 e8 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? 46 00 68 80 88 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 68 f4 01 00 00 ff d6 8b 55 1c } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}