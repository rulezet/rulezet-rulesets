rule TrojanProxy_Win32_Wonknod_D{
	meta:
		description = "TrojanProxy:Win32/Wonknod.D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 73 76 63 76 6d 78 } 		$a_00_1 = {53 56 43 56 4d 58 7b 37 32 43 45 38 44 42 30 2d 36 45 42 36 2d 34 43 32 34 2d 39 32 45 38 2d 41 30 37 42 37 37 41 32 32 39 46 38 7d } 		$a_03_2 = {61 00 69 00 c7 ?? ?? 6e 00 7b 00 c7 ?? ?? 30 00 37 00 c7 ?? ?? 36 00 37 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*10) >=12
 
}