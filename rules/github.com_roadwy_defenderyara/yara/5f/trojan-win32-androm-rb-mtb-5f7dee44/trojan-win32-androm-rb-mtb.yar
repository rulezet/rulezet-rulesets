rule Trojan_Win32_Androm_RB_MTB{
	meta:
		description = "Trojan:Win32/Androm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 8b c8 0f be c2 80 fa 61 7c 03 83 e8 20 8a 56 01 46 03 c8 84 d2 75 e0 8b c1 5e c3 } 		$a_01_1 = {cc cc c1 c9 0d 8b c1 c3 cc cc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}