rule Trojan_Win32_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {86 0e 0a 01 01 b9 6c 01 01 01 67 8a 86 e9 e7 00 00 ba 66 01 01 01 67 8a 8e eb e7 00 00 bb 73 01 01 01 67 8a 96 ed e7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}