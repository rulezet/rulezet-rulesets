rule Rogue_Win32_FakeSecSen{
	meta:
		description = "Rogue:Win32/FakeSecSen,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 6e 6b 6e 6f 77 6e 20 46 69 6c 65 20 46 6f 75 6e 64 00 00 ff ff ff ff 0d 00 00 00 4d 61 6c 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 53 70 79 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0c 00 00 00 41 64 77 61 72 65 20 46 6f 75 6e 64 00 00 00 00 ff ff ff ff 0f 00 00 00 53 61 66 65 20 46 69 6c 65 20 46 6f 75 6e 64 00 ff ff ff ff 15 00 00 00 53 75 73 70 69 63 69 6f 75 73 20 46 69 6c 65 20 46 6f 75 6e 64 } 		$a_01_1 = {49 45 20 41 6e 74 69 76 69 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}