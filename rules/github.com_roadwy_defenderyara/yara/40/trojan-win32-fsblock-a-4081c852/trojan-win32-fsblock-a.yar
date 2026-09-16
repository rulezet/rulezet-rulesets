rule Trojan_Win32_Fsblock_A{
	meta:
		description = "Trojan:Win32/Fsblock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 } 		$a_01_1 = {e1 eb ee ea e8 f0 ee e2 } 		$a_03_2 = {6f 70 3d cc d2 d1 3b ?? ?? 3b 6e 75 6d 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}