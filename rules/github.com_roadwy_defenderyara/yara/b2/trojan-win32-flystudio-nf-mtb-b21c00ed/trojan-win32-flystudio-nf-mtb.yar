rule Trojan_Win32_Flystudio_NF_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 39 1d ?? ?? ?? ?? 56 57 75 05 e8 44 fd ff ff be b0 f1 4d } 		$a_03_1 = {a1 64 08 4e 00 89 35 ?? ?? ?? ?? 8b fe 38 18 74 02 8b f8 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}