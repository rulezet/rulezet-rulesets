rule Backdoor_Win32_Caphaw_X{
	meta:
		description = "Backdoor:Win32/Caphaw.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 45 e0 50 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b f8 85 ff 74 ?? 68 e8 03 00 00 57 ff 15 ?? ?? ?? 00 3d 02 01 00 00 74 ?? 68 e8 03 00 00 ff 15 ?? ?? ?? 00 } 		$a_01_1 = {53 55 8b 6c 24 18 56 8b 74 24 10 57 8b 7c 24 1c 8d 64 24 00 8b ca 83 e1 1f bb 01 00 00 00 d3 e3 85 dd 74 09 8a 0e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}