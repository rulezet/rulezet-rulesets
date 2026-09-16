rule Trojan_Win32_MemCCDump_A_POS_2{
	meta:
		description = "Trojan:Win32/MemCCDump.A!POS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 72 64 4e 75 6d 62 65 72 22 3e 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 3c 2f 46 69 65 6c 64 3e 29 7c 28 7e 43 43 4d 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 44 5b 30 2d 39 5d 7b 34 7d 7e 29 29 00 } 		$a_01_1 = {46 6f 75 6e 64 20 74 72 61 63 6b 20 64 61 74 61 20 61 74 20 25 73 20 77 69 74 68 20 50 49 44 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}