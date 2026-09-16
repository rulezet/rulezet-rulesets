rule Backdoor_Win32_Escad_J_dha_5{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 25 73 } 		$a_01_1 = {48 61 48 61 48 61 5f 25 64 25 64 25 64 25 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}