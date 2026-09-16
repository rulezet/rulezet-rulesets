rule Ransom_Win32_FileEncoder_A_MTB{
	meta:
		description = "Ransom:Win32/FileEncoder.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75 ed } 		$a_03_1 = {bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? ?? ?? 80 e9 41 c7 05 ?? ?? ?? ?? 3a 5c 2a 2e c6 05 ?? ?? ?? ?? 2a c6 05 ?? ?? ?? ?? 00 50 51 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}