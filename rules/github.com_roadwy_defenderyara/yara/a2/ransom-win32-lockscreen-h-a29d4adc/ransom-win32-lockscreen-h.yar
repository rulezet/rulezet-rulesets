rule Ransom_Win32_LockScreen_H{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad } 		$a_01_1 = {74 13 34 0e 66 0f b6 c0 42 66 89 01 8a 02 83 c1 02 3c 0e 75 ed } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}