rule Trojan_Win32_CryptInject_BG_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 65 52 4c 4f 5f 70 72 6f 6a 65 63 74 5c 50 72 6f 6a 65 74 5f 32 5c 70 72 6f 6a 65 63 74 5c 68 61 63 6b 65 72 6c 6f 5c 52 65 6c 65 61 73 65 5c 68 61 63 6b 65 72 6c 6f 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}