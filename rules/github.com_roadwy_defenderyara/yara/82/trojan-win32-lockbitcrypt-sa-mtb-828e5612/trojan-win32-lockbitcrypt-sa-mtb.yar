rule Trojan_Win32_LockbitCrypt_SA_MTB{
	meta:
		description = "Trojan:Win32/LockbitCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b fb c1 e7 04 81 3d ?? ?? ?? ?? 6f 03 00 00 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8b f3 c1 ee 05 03 75 ?? 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 } 		$a_01_1 = {51 6a 40 50 52 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}