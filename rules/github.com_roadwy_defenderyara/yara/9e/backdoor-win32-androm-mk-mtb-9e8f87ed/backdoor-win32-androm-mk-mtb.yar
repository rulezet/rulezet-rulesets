rule Backdoor_Win32_Androm_MK_MTB{
	meta:
		description = "Backdoor:Win32/Androm.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {e9 00 00 00 5c 14 40 00 5c 14 40 00 18 14 40 00 78 } 		$a_01_1 = {94 26 85 00 24 15 40 00 7c 1e 40 00 a0 1e 40 } 	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}