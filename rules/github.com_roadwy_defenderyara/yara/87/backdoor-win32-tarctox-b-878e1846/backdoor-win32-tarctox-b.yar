rule Backdoor_Win32_Tarctox_B{
	meta:
		description = "Backdoor:Win32/Tarctox.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 2b 45 08 c1 e8 02 89 45 fc 33 c0 8b 4d fc 51 8b d1 4a c1 e2 02 03 55 08 81 32 ?? ?? 00 00 59 49 0b c9 75 02 eb 02 eb e6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}