rule Trojan_Win32_Guloader_BAA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 85 d2 85 db 5b 66 85 d2 66 3d ?? ?? 01 d3 66 85 c0 66 85 c0 31 0b e9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}