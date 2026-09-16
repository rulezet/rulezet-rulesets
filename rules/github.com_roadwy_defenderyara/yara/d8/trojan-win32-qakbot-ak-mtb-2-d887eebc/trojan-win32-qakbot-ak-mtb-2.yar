rule Trojan_Win32_Qakbot_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 79 72 74 68 79 33 34 35 74 33 34 35 74 32 34 72 74 34 74 72 67 79 77 65 72 66 61 64 6a 66 6f 69 6f 75 61 68 75 66 68 61 73 75 } 		$a_01_1 = {eb c0 7c 50 be ca 6b 41 c8 c1 7a 65 bf d6 08 00 ac a5 08 56 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}