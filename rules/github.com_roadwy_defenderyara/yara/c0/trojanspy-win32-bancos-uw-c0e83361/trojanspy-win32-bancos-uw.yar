rule TrojanSpy_Win32_Bancos_UW{
	meta:
		description = "TrojanSpy:Win32/Bancos.UW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 78 44 61 74 61 2e 64 6c 6c 00 49 41 53 46 48 42 49 41 53 53 56 4e 41 54 53 53 00 } 		$a_01_1 = {54 59 58 4f 4d 41 53 4b 51 57 42 46 48 59 55 57 45 49 47 48 4e 02 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=10
 
}