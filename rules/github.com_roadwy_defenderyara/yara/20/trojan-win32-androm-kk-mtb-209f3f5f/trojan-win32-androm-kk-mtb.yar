rule Trojan_Win32_Androm_KK_MTB{
	meta:
		description = "Trojan:Win32/Androm.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 19 99 59 f7 f9 80 c2 61 88 54 35 c0 46 83 fe 07 } 		$a_01_1 = {68 79 74 72 37 66 69 73 67 66 68 74 72 6f 33 39 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}