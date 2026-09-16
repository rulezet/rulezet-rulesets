rule Trojan_Win32_KillWin_ARR_MTB{
	meta:
		description = "Trojan:Win32/KillWin.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 0f 45 d5 0b 54 31 ?? 0b d7 83 e2 17 } 		$a_01_1 = {54 41 53 4b 52 4f 55 54 49 4e 45 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 } 		$a_01_2 = {52 65 67 69 73 74 72 79 20 6c 6f 67 67 69 6e 67 20 69 73 20 44 49 53 41 42 4c 45 44 20 28 54 41 53 4b 52 4f 55 54 49 4e 45 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 3d 31 29 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*12+(#a_01_2  & 1)*6) >=20
 
}