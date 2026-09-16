rule Trojan_Win32_Tasker_A_MTB{
	meta:
		description = "Trojan:Win32/Tasker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 49 02 49 81 e9 06 00 00 00 49 63 d2 44 0f ab fa 66 44 0f ac f2 9f 66 41 d3 e0 0f b7 d7 49 0f bf d0 66 45 89 41 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}