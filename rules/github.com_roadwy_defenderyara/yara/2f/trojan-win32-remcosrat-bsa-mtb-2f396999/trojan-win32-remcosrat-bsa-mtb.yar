rule Trojan_Win32_RemcosRAT_BSA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 e8 18 0c fb ff 83 f8 01 1b c0 40 84 c0 0f 84 98 00 00 00 b3 01 83 } 		$a_81_1 = {41 6d 73 69 49 6e 69 74 69 61 6c 69 7a 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}