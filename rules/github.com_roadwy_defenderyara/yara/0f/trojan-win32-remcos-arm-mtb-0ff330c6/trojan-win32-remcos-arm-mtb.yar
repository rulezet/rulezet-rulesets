rule Trojan_Win32_Remcos_ARM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 8d a0 01 43 00 8b f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 a0 05 43 00 41 89 04 8d 9c 05 43 00 3b ca } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}