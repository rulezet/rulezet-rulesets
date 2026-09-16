rule Trojan_Win32_Encoder_B{
	meta:
		description = "Trojan:Win32/Encoder.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 69 6c 65 57 61 6c 6c 70 61 70 65 72 } 		$a_00_1 = {38 31 38 32 35 30 39 35 30 38 36 34 30 33 31 37 37 37 30 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}