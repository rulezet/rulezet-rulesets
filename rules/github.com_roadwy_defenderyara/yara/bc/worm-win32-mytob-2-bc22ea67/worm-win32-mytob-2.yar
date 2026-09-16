rule Worm_Win32_Mytob_2{
	meta:
		description = "Worm:Win32/Mytob,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4d 79 52 65 61 6c 4e 61 6d 65 [0-10] 4e 54 53 68 65 6c 6c 20 54 61 73 6b 6d 61 6e 20 53 74 61 72 74 75 70 20 4d 75 74 65 78 [0-10] 5c 74 61 73 6b 6d 67 72 2e 65 78 65 [0-10] 75 73 65 72 33 32 2e 64 6c 6c [0-10] 50 72 6f 67 6d 61 6e [0-10] 50 72 6f 67 72 61 6d 20 4d 61 6e 61 67 65 72 [0-10] 4f 55 54 50 4f 53 54 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}