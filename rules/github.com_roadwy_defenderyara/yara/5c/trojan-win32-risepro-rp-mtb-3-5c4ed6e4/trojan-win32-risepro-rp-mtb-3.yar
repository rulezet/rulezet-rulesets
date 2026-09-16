rule Trojan_Win32_RisePro_RP_MTB_3{
	meta:
		description = "Trojan:Win32/RisePro.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 74 61 67 67 61 6e 74 00 30 00 00 00 ?? ?? ?? ?? 22 00 00 } 		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 78 36 34 } 		$a_01_2 = {50 6c 65 61 73 65 2c 20 63 6f 6e 74 61 63 74 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 64 65 76 65 6c 6f 70 65 72 73 20 77 69 74 68 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 63 6f 64 65 73 2e 20 54 68 61 6e 6b 20 79 6f 75 2e } 		$a_01_3 = {50 6c 65 61 73 65 2c 20 63 6f 6e 74 61 63 74 20 79 6f 75 72 73 69 74 65 40 79 6f 75 72 73 69 74 65 2e 63 6f 6d 2e 20 54 68 61 6e 6b 20 79 6f 75 21 } 		$a_01_4 = {04 64 a0 59 40 05 ce 0a 40 05 ce 0a 40 05 ce 0a 1b 6d cd 0b 51 05 ce 0a 1b 6d cb 0b e0 05 ce 0a 95 68 ca 0b 52 05 ce 0a 95 68 cd 0b 57 05 ce 0a 95 68 cb 0b 35 05 ce 0a 1b 6d ca 0b 55 05 ce 0a 1b 6d cf 0b 53 05 ce 0a 40 05 cf 0a 94 05 ce 0a db 6b c7 0b 41 05 ce 0a db 6b 31 0a 41 05 ce 0a db 6b cc 0b 41 05 ce 0a 52 69 63 68 40 05 ce 0a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}