rule Backdoor_Win32_Dridex_2{
	meta:
		description = "Backdoor:Win32/Dridex,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {ec e7 57 06 c7 45 ff c5 27 6e fb c7 45 03 c9 3c 83 63 c7 45 07 a9 74 0b cd e8 6f 23 03 00 4c 89 75 ef 41 8b fe 48 8d 4d d7 e8 4b 2d 03 00 48 8d } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}