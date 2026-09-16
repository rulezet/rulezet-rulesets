rule Trojan_Win32_Remcos_ARM_MTB_4{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 54 5f 5f 33 36 34 37 39 35 33 38 31 39 80 03 00 00 02 00 0d 54 5f 5f 33 36 34 37 39 36 32 35 37 30 84 03 00 00 02 00 0d 54 5f 5f 33 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}