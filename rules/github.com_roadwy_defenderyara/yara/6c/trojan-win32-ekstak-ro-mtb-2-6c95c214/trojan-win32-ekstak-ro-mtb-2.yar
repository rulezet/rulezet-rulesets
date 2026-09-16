rule Trojan_Win32_Ekstak_RO_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 68 53 ff 64 00 e8 b5 71 fb ff 8b f0 e9 } 		$a_00_1 = {56 68 2f df 64 00 e8 c5 71 fb ff 8b f0 e9 } 	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*5) >=5
 
}