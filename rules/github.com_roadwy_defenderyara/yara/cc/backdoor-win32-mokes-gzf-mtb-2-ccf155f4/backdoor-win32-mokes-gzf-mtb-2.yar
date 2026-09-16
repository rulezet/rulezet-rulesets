rule Backdoor_Win32_Mokes_GZF_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 5d c0 06 09 f9 b0 79 a4 52 b6 f3 45 94 56 35 ?? ?? ?? ?? b8 ?? ?? ?? ?? 07 b9 ?? ?? ?? ?? 69 0b } 		$a_03_1 = {98 0e 31 5a ?? 22 c1 4f eb } 		$a_03_2 = {01 ed b1 30 d0 30 30 29 9e 53 aa 35 ?? ?? ?? ?? 07 95 39 78 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=10
 
}