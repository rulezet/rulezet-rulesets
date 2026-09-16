rule Trojan_Win32_Tracur_A{
	meta:
		description = "Trojan:Win32/Tracur.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 32 9a ?? ?? 40 00 83 c2 01 3b d5 88 5c 0e ff 75 02 33 d2 83 c1 01 3b cf 7e e3 5b 5f 88 44 31 ff 5d c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}