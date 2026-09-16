rule Trojan_Win32_Spycos_H_2{
	meta:
		description = "Trojan:Win32/Spycos.H,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}