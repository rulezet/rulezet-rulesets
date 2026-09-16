rule Backdoor_Win32_Farfli_BAA_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 0f b7 d1 8a 94 55 ?? ?? ?? ?? 30 10 41 40 4e 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}