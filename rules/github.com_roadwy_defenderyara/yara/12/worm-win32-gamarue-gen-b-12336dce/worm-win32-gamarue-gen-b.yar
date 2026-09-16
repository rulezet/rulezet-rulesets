rule Worm_Win32_Gamarue_gen_B{
	meta:
		description = "Worm:Win32/Gamarue.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 07 fd e5 4c 0f 84 ?? ?? 00 00 3d 6c 32 81 81 0f 84 ?? ?? 00 00 3d af 33 e2 31 0f 84 ?? ?? 00 00 3d f6 7d d4 91 0f 84 ?? ?? 00 00 3d 54 dc cd e8 0f 84 ?? ?? 00 00 3d 6c 6d 8c 00 0f 84 ?? ?? 00 00 3d 0e ba d0 a8 0f 84 ?? ?? 00 00 3d 0e 3c ef a4 0f 84 ?? ?? 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}