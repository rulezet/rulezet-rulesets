rule Trojan_Win32_Convagent_ARR_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 52 8d 54 3c 14 68 } 		$a_01_1 = {8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*8) >=10
 
}