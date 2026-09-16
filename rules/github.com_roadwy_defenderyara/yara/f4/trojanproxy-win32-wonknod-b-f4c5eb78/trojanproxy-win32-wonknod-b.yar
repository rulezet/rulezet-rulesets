rule TrojanProxy_Win32_Wonknod_B{
	meta:
		description = "TrojanProxy:Win32/Wonknod.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 25 64 2c c7 45 ?? 70 69 64 3d } 		$a_01_1 = {5c 56 43 20 50 72 6f 6a 65 63 74 5c 42 79 70 61 73 73 55 61 63 5c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}