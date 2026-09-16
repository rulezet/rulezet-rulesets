rule Trojan_Win32_Amadey_AMY_MTB_5{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51 c7 84 24 18 02 00 00 84 82 10 45 c7 84 24 08 01 00 00 80 d9 0f 28 c7 84 24 20 01 00 00 5a 91 84 3c c7 84 24 ac 01 00 00 c2 99 3e 72 c7 84 24 e0 00 00 00 f4 09 87 1b c7 84 24 00 02 00 00 d9 b0 ba 48 c7 84 24 50 01 00 00 02 a6 fb 09 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}