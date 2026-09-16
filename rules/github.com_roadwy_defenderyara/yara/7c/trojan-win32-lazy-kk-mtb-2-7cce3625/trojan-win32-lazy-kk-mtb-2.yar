rule Trojan_Win32_Lazy_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c b1 b5 01 db dd 33 c6 6e 32 97 4c 65 3e 9c } 		$a_01_1 = {ac 32 c4 fe c4 c0 c4 02 80 c4 90 aa e2 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}