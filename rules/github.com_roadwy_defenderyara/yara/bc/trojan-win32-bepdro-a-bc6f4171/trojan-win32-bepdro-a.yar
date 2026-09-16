rule Trojan_Win32_Bepdro_A{
	meta:
		description = "Trojan:Win32/Bepdro.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 66 75 63 6b 00 00 00 ff ff ff ff 2d 00 00 00 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 00 00 ff ff ff ff 22 00 00 00 25 57 69 6e 44 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}