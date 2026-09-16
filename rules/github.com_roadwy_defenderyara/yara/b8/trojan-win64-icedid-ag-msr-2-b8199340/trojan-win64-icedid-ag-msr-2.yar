rule Trojan_Win64_IcedID_AG_MSR_2{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff cf 4c 0f ac f6 5e 48 c1 e6 5e 49 c1 ee 15 4d 3b e3 49 c7 c6 be 15 00 00 48 f7 e2 49 f7 db 4d 69 ff 81 0e 00 00 48 33 d2 e4 fe 48 33 c9 48 f7 f1 48 ff c6 48 0f ac fd 6e 48 c1 e5 6e 4d 8b c6 48 ff cd 48 69 c0 ee 1b 00 00 48 f7 c3 5a 17 00 00 48 f7 d3 41 5f 48 33 ed 49 81 e2 40 1b 00 00 48 ff cd 49 81 d5 c7 04 00 00 49 ff cc 49 f7 d6 49 83 fd 2e 49 81 dc e9 07 00 00 4d 33 c0 4c 3b d5 49 81 e3 45 16 00 00 c8 b3 00 00 90 e4 f9 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}