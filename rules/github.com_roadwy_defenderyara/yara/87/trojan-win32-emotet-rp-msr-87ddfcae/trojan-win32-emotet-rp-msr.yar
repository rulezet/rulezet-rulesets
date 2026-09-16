rule Trojan_Win32_Emotet_RP_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 38 5c 57 69 6e 33 32 5f 2d 5f 49 45 31 32 30 31 34 35 38 31 39 32 30 30 32 5c 52 65 6c 65 61 73 65 5c 49 45 5f 4d 45 4e 55 42 41 52 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}