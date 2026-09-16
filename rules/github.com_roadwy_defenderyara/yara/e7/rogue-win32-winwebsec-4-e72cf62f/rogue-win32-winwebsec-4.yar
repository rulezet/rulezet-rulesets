rule Rogue_Win32_Winwebsec_4{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {ec 64 6d 02 8d 0a 3e 02 8d 0a 3e 02 8d 0a 3e 1c df 9f 3e 1f 8d 0a 3e 1c df 89 3e 83 8d 0a 3e 1c df 8e 3e 31 8d 0a 3e 25 4b 67 3e 0a 8d 0a 3e 25 4b 71 3e 1f 8d 0a 3e 02 8d 0b 3e 6a 8c 0a 3e 01 } 		$a_55_1 = {58 21 0d 09 08 09 f1 1a 1c 6a 5c ab e5 23 00 00 78 } 	condition:
		((#a_11_0  & 1)*1+(#a_55_1  & 1)*4096) >=2
 
}