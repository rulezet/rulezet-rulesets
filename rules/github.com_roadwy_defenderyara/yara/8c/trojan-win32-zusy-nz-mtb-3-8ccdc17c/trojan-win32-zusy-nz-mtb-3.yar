rule Trojan_Win32_Zusy_NZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 6f fd ff ff 8b 4c 24 ?? 8b 54 24 08 85 c9 88 48 14 89 ?? ?? ?? ?? ?? 75 09 6a fd ff 15 2c 32 } 		$a_01_1 = {70 00 72 00 6f 00 2e 00 70 00 61 00 72 00 74 00 72 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}