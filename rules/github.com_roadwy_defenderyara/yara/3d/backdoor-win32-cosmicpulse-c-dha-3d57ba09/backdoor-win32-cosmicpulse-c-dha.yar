rule Backdoor_Win32_CosmicPulse_C_dha{
	meta:
		description = "Backdoor:Win32/CosmicPulse.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 6b 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 31 00 32 00 2f 00 } 		$a_01_1 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 5c 00 73 00 63 00 68 00 6c 00 61 00 6e 00 67 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}