rule Trojan_Win32_Ekstak_GAN_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 67 53 80 00 89 b7 7c 00 00 be 0a 00 d4 bd 14 99 0c 7b ?? ?? 00 d4 00 00 1e } 		$a_03_1 = {2a 01 00 00 00 2c 96 80 00 4e fa 7c 00 00 be 0a 00 d4 bd 14 99 ef bd ?? ?? 00 d4 00 00 } 		$a_01_2 = {2a 01 00 00 00 23 13 6b 00 45 77 67 00 00 be 0a 00 d4 bd 14 99 f4 30 67 00 00 d4 00 00 b4 21 } 		$a_01_3 = {2a 01 00 00 00 d3 d7 6b 00 f5 3b 68 00 00 be 0a 00 d4 bd 14 99 77 f5 67 00 00 d4 00 00 df } 		$a_01_4 = {2a 01 00 00 00 30 0c 6b 00 52 70 67 00 00 be 0a 00 d4 bd 14 99 d8 29 67 00 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=10
 
}