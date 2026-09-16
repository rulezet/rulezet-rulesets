rule Trojan_Win32_Copack_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 f8 09 ff e8 1c 00 00 00 29 c0 81 e8 01 00 00 00 31 16 81 e8 ?? ?? ?? ?? 46 01 c7 39 de 75 db 89 f8 29 c0 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}