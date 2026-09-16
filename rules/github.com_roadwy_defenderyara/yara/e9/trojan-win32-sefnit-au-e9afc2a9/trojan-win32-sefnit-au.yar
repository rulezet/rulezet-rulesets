rule Trojan_Win32_Sefnit_AU{
	meta:
		description = "Trojan:Win32/Sefnit.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {bb 8c ac 00 00 66 33 1c 01 66 89 18 03 c7 4a } 		$a_01_1 = {e4 ac f8 ac f8 ac fc ac b6 ac a3 ac a3 ac ff ac fe ac fa ac f9 ac fc ac e8 ac a2 ac e2 ac e9 ac f8 ac } 		$a_01_2 = {bb ed a2 00 00 66 33 1c 01 66 89 18 83 c0 02 } 		$a_01_3 = {9e a2 88 a2 9f a2 9b a2 84 a2 8e a2 88 a2 c0 a2 9e a2 99 a2 8c a2 99 a2 c3 a2 8e a2 82 a2 80 a2 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=1
 
}