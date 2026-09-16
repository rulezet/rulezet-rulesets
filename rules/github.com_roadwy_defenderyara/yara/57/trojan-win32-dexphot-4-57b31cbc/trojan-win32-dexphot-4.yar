rule Trojan_Win32_Dexphot_4{
	meta:
		description = "Trojan:Win32/Dexphot,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 63 65 73 73 4d 64 69 6e 6f 63 65 73 73 4d 69 64 73 73 4d 69 6e 69 6e 6f 63 65 73 73 4d 69 6e 64 6f 63 65 73 73 4d 69 6e 69 6e 6f 63 65 73 73 4d 69 6e 69 6e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}