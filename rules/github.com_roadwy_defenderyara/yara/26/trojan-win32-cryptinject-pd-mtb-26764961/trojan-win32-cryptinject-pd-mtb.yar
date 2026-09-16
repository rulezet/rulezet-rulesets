rule Trojan_Win32_CryptInject_PD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 95 00 ff ff ff 88 55 e3 0f be 45 ef 83 e0 0f c1 e0 04 0f be 4d e3 83 e1 0f 0b c1 8b 55 0c 03 55 c8 88 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}