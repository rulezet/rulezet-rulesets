rule Trojan_Win32_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 cc 4c b3 0a 81 aa ?? ?? ?? ?? 45 a8 93 fb 0c 67 13 4b ?? 7e f3 ff b3 9f bb b9 b5 } 		$a_01_1 = {31 cf 44 e2 23 86 f3 69 7d e2 a0 3d 7f 43 04 02 45 e6 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}