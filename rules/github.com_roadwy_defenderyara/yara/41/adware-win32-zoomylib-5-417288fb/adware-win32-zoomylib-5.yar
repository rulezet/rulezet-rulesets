rule Adware_Win32_ZoomyLib_5{
	meta:
		description = "Adware:Win32/ZoomyLib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 ff 15 ?? ?? ?? ?? 8b d8 85 c0 74 10 ba 20 4e 00 00 48 8b cf ff 15 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 85 db 75 db 33 c9 e8 ?? ?? ?? ?? cc 48 8b c4 55 48 8d a8 98 fc ff ff 48 81 ec 60 04 00 00 } 		$a_03_1 = {48 8b 5c 24 20 48 8b cb ff 15 ?? ?? ?? ?? 48 85 c0 74 18 48 8d 15 ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 74 03 ff d0 } 		$a_01_2 = {48 8d 53 e8 f0 83 42 10 ff 7f 16 48 8b 0a 48 8b 01 ff 50 08 eb 0b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}