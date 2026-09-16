rule Trojan_Win32_Copak_BAK_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 34 32 21 f8 8b 36 bf ?? ?? ?? ?? 48 89 ff 81 e6 ff 00 00 00 89 f8 42 89 c0 01 f8 81 c7 01 00 00 00 81 fa f4 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}