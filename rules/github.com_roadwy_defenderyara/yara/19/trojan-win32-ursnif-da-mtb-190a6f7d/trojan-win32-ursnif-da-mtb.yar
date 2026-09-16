rule Trojan_Win32_Ursnif_DA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a da 89 15 ?? ?? ?? ?? 02 db 80 c3 0d 8b 54 24 28 8a c1 2a 44 24 10 81 c6 04 9c 01 01 2c 52 89 35 ?? ?? ?? ?? 02 d8 8b 44 24 24 89 34 02 83 c0 04 8b 15 ?? ?? ?? ?? 89 44 24 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}