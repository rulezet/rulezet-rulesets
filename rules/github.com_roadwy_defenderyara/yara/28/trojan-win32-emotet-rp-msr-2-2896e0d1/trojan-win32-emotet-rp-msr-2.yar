rule Trojan_Win32_Emotet_RP_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.RP!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 33 45 d4 89 45 f8 8b 45 f8 c1 e0 1f c1 f8 1f 89 c2 81 e2 96 30 07 77 8b 45 f8 c1 e0 1e c1 f8 1f 25 2c 61 0e ee 31 c2 8b 45 f8 c1 e0 1d c1 f8 1f 25 19 c4 6d 07 31 c2 8b 45 f8 c1 e0 1c c1 f8 1f 25 32 88 db 0e 31 c2 8b 45 f8 c1 e0 1b c1 f8 1f 25 64 10 b7 1d 31 c2 8b 45 f8 c1 e0 1a c1 f8 1f 25 c8 20 6e 3b 31 c2 8b 45 f8 c1 e0 19 c1 f8 1f 25 90 41 dc 76 31 c2 8b 45 f8 c1 e0 18 c1 f8 1f 25 20 83 b8 ed 31 d0 89 45 d0 8b 45 f8 c1 e8 08 33 45 d0 89 45 f8 ff 45 fc 8b 55 fc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}