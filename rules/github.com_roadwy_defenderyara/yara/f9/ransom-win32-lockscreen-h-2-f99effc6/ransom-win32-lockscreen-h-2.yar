rule Ransom_Win32_LockScreen_H_2{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad } 		$a_03_1 = {77 03 80 c1 ?? 0f be c9 69 c9 ?? 00 00 00 03 c8 c1 c1 ?? 8b c1 8a 0a 84 c9 75 dc } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}