rule Trojan_Win32_Rootkit_F{
	meta:
		description = "Trojan:Win32/Rootkit.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 50 4f 43 20 52 6f 6f 74 6b 69 74 } 		$a_03_1 = {8d 44 00 02 50 8d 85 ?? ?? ff ff 50 68 04 20 22 00 ff 35 ?? ?? 40 00 } 		$a_03_2 = {8d 44 00 02 50 8d 85 ?? ?? ff ff 50 68 08 20 22 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 eb 10 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}