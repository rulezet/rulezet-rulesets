rule Trojan_Win32_Nibtse_A{
	meta:
		description = "Trojan:Win32/Nibtse.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 [0-08] 20 00 68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 90 2f 10 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}