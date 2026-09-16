rule Backdoor_Win32_Escad_J_dha{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 08 33 c7 83 c1 04 c1 e0 08 33 c3 c1 e0 08 8b d0 33 d5 8b c2 89 91 } 		$a_00_1 = {73 6b 69 6e 70 66 75 2e 64 61 74 } 		$a_00_2 = {73 6b 6d 73 76 78 64 2e 64 61 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}