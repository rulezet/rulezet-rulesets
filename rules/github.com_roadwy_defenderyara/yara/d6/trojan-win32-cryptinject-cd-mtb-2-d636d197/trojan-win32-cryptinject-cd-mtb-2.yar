rule Trojan_Win32_CryptInject_CD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {7e 08 81 f9 d0 a6 8f 34 75 08 40 3d aa 8f e0 14 7c e9 } 		$a_02_1 = {81 fe 01 3f 14 22 7c cd a1 ?? ?? ?? ?? 8b f7 05 3b 2d 0b 00 a3 ?? ?? ?? ?? 81 fe 89 62 65 00 75 10 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 46 81 fe 56 d0 66 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}