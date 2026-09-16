rule Backdoor_Win32_Poison_I_2{
	meta:
		description = "Backdoor:Win32/Poison.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 5a 8d bd ?? ?? ff ff 8d 9d ?? ?? ff ff 68 b6 30 0a a1 ff b6 ?? ?? 00 00 ff b6 e1 00 00 00 ff 96 dd 00 00 00 } 		$a_00_1 = {57 6a 01 57 ff 75 fc 6a 00 56 ff 96 e5 00 00 00 81 7f fd 0d 0a 0d 0a 75 02 eb 05 83 c7 01 eb e1 5f 81 3f 35 30 33 20 0f 84 9e fe ff ff 81 7f 09 32 30 30 20 } 		$a_02_2 = {ff 96 e5 00 00 00 56 fc b9 40 00 00 00 8d b5 ?? ?? ff ff 8d bd ?? ?? ff ff f3 a7 74 0d 5e c7 85 ?? ?? ff ff 30 75 00 00 eb 7f 5e 6a 04 8d 45 f8 50 ff 75 fc 6a 00 56 ff 96 e5 00 00 00 85 c0 74 68 6a 40 68 00 10 00 00 ff 75 f8 6a 00 ff 56 21 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}