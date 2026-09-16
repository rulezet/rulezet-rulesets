rule Trojan_Win32_Emotet_ABE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 58 48 67 57 4c 53 77 41 65 62 3c 61 78 78 5e 35 5a 47 61 53 55 3f 29 71 37 30 50 4c 75 2b 71 64 23 70 25 33 73 38 32 51 37 24 21 6b 78 63 57 39 23 6f 40 56 56 37 54 4d 52 55 44 3c 76 76 23 6c 4d 28 42 73 39 52 2a 6c 50 4a 6d 64 65 21 69 5a 36 4c 38 52 6f 6c 23 2b 65 3f 4c 32 50 3f 38 37 5f 6e 31 5a 79 71 6a 37 68 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}