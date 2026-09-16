rule Trojan_Win32_CryptInject_BU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {ac 32 02 aa 42 49 83 ec 04 c7 04 24 93 dc 00 05 83 c4 04 85 c9 75 } 		$a_01_1 = {ac 83 ec 04 c7 04 24 5e d0 7d db 83 c4 04 32 02 aa 42 49 85 c9 75 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}