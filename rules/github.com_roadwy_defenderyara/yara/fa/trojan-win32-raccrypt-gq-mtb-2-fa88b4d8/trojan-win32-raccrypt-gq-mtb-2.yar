rule Trojan_Win32_Raccrypt_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {88 0c 02 40 3b 05 } 		$a_02_1 = {03 c8 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 55 ?? 33 d1 33 d3 8d 8d ?? ?? ?? ?? 89 55 ?? 90 18 29 11 c3 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}