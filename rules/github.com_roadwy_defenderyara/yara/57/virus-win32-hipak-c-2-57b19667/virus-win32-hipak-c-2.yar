rule Virus_Win32_Hipak_C_2{
	meta:
		description = "Virus:Win32/Hipak.C,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 84 0d 58 f2 ff ff 5c 41 c6 84 0d 58 f2 ff ff 64 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 69 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 72 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 5c 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 63 41 c6 84 0d 58 f2 ff ff 68 41 c6 84 0d 58 f2 ff ff 6f 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 2e 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 78 41 c6 84 0d } 		$a_01_1 = {58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 20 41 c6 84 0d 58 f2 ff ff 2f 41 c6 84 0d 58 f2 ff ff 61 41 8d bd 58 f2 ff ff 8d 95 fc fe ff ff c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 6f 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 6e } 		$a_01_2 = {6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 00 00 00 6b 73 63 76 00 00 00 00 49 6e 65 74 49 6e 66 6f 00 00 00 00 30 34 00 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}